#!/usr/bin/env bash
#
# Compares a Go coverage profile with the minimums in coverage-floors.txt, for each
# package and for the module as a whole.
#
# Arguments are the profile and the floors file, in that order, and default to
# .coverage/coverage.out and coverage-floors.txt. By default the result is only printed;
# COVERAGE_ENFORCE=1 turns a violation into a non-zero exit. Packages without a floor are
# listed but cannot fail. Raise a floor as tests are added, and never lower one.
set -euo pipefail

profile="${1:-.coverage/coverage.out}"
floors_file="${2:-coverage-floors.txt}"
enforce="${COVERAGE_ENFORCE:-0}"
module_prefix="$(go list -m)/"

die() {
	echo "coverage-gate: $*" >&2
	exit 1
}

[[ -f "$profile" ]] || die "profile not found: $profile (run 'make test' first)"
# Checked with -s because the program below recognises its first input by FNR==NR. Given an
# empty floors file, it would take the profile for the floors and report nothing useful.
[[ -s "$floors_file" ]] || die "floors file missing or empty: $floors_file"

awk -v module="$module_prefix" -v enforce="$enforce" '
	function read_floor(text,    parts) {
		sub(/#.*/, "", text)
		gsub(/^[ \t]+|[ \t]+$/, "", text)
		if (text == "") return
		split(text, parts, /[ \t]+/)
		if (parts[1] == "TOTAL") {
			total_floor = parts[2] + 0
			has_total_floor = 1
		} else if (parts[1] == "EXCLUDE") {
			excluded[parts[2]] = 1
		} else {
			floors[parts[1]] = parts[2] + 0
		}
	}

	# Turns "<module>/some/pkg/file.go:12.3,14.5" into "some/pkg".
	function package_of(block,    path) {
		path = block
		sub(/:[0-9].*/, "", path)
		sub(/\/[^\/]*$/, "", path)
		sub(module, "", path)
		return path
	}

	function percent(covered, statements) {
		return statements > 0 ? 100.0 * covered / statements : 0
	}

	function sort_names(names, count,    i, j, name) {
		for (i = 2; i <= count; i++) {
			name = names[i]
			for (j = i - 1; j >= 1 && names[j] > name; j--) names[j + 1] = names[j]
			names[j + 1] = name
		}
	}

	FNR == NR { read_floor($0); next }

	# The first profile line only names the cover mode.
	FNR == 1 { next }

	# With -coverpkg every test binary reports each block it compiled, so one block can be
	# listed many times. It counts as covered if any binary ran it, hence the maximum.
	{
		block = $1
		if (!(block in block_statements)) {
			block_statements[block] = $2 + 0
			block_package[block] = package_of(block)
			profiled[block_package[block]] = 1
		}
		if ($3 + 0 > block_runs[block]) block_runs[block] = $3 + 0
	}

	END {
		for (block in block_statements) {
			pkg = block_package[block]
			statements = block_statements[block]
			ran = block_runs[block] > 0
			package_statements[pkg] += statements
			if (ran) package_covered[pkg] += statements
			if (!(pkg in excluded)) {
				module_statements += statements
				if (ran) module_covered += statements
			}
		}

		violated = 0
		printf "%-54s %8s %7s\n", "PACKAGE", "COVER", "FLOOR"
		count = 0
		for (pkg in profiled) names[++count] = pkg
		sort_names(names, count)
		for (row = 1; row <= count; row++) {
			pkg = names[row]
			coverage = percent(package_covered[pkg], package_statements[pkg])
			note = (pkg in excluded) ? " (excluded)" : ""
			shown = (pkg in floors) ? sprintf("%d", floors[pkg]) : "-"
			if ((pkg in floors) && coverage + 0.0001 < floors[pkg]) {
				note = note "  <-- BELOW FLOOR"
				violated = 1
			}
			printf "%-54s %7.1f%% %7s%s\n", pkg, coverage, shown, note
		}

		# A floor for a package that has been renamed or removed would otherwise go on
		# passing without measuring anything.
		for (pkg in floors) {
			if (!(pkg in profiled)) {
				printf "%-54s missing from the profile  <-- STALE FLOOR\n", pkg
				violated = 1
			}
		}

		coverage = percent(module_covered, module_statements)
		shown = has_total_floor ? sprintf("%d", total_floor) : "-"
		printf "\n%-54s %7.1f%% %7s\n", "TOTAL (excludes EXCLUDE pkgs)", coverage, shown
		if (has_total_floor && coverage + 0.0001 < total_floor) {
			print "  <-- TOTAL BELOW FLOOR"
			violated = 1
		}

		if (!violated) {
			print "\ncoverage-gate: OK"
		} else if (enforce == "1") {
			print "\ncoverage-gate: FAIL (enforced)"
			exit 1
		} else {
			print "\ncoverage-gate: violations found (report-only; set COVERAGE_ENFORCE=1 to enforce)"
		}
	}
' "$floors_file" "$profile"
