#!/bin/sh

set -eu

INDEX="$1"

PROJECTS="$(cut -d':' -f1 "$INDEX")"
COMMANDS="tidy get build test up"

TAB=$(printf "\t")

escape_dir() {
	echo "$1" | sed -e 's|/|\\/|g' -e 's|\.|\\.|g'
}

expand() {
	local prefix="$1" suffix="$2"
	local x= out=
	shift 2

	for x; do
		out="${out:+$out }${prefix}$x${suffix}"
	done

	echo "$out"
}

prefixed() {
	local prefix="${1:+$1-}"
	shift
	expand "$prefix" "" "$@"
}

suffixed() {
	local suffix="${1:+-$1}"
	shift
	expand "" "$suffix" "$@"
}

# packed remove excess whitespace from lines of commands
packed() {
	sed -e 's/^[ \t]\+//' -e 's/[ \t]\+$//' -e '/^$/d;' -e '/^#/d';
}

# packet_oneline converts a multiline script into packed single-line equivalent
packed_oneline() {
	packed | tr '\n' ';' | sed -e 's|;$||' -e 's|then;|then |g' -e 's|;[ \t]*|; |g'
}

gen_install_tools() {
	cat <<EOT
for url in \$(GO_INSTALL_URLS); do \$(GO) install -v \$\$url; done
EOT
}

gen_revive_exclude() {
	local self="$1"
	local dirs= d=

	dirs="$(cut -d: -f2 "$INDEX" | grep -v '^.$' || true)"
	if [ "." != "$self" ]; then
		dirs=$(echo "$dirs" | sed -n -e "s;^$self/\(.*\)$;\1;p")
	fi

	for d in $dirs; do
		printf -- "-exclude ./$d/... "
	done
}

gen_var_name() {
	local x=
	for x; do
		echo "$x" | tr 'a-z-' 'A-Z_'
	done
}

# generate files lists
#
gen_files_lists() {
	local name= dir= mod= deps=
	local files= files_cmd=
	local filter= out_pat=

	cat <<EOT
GO_FILES = \$(shell find * \\
	-type d -name node_modules -prune -o \\
	-path pkg/internal/build -prune -o \\
	-type f -name '*.go' -print )

EOT

	while IFS=: read name dir mod deps; do
		files=GO_FILES_$(gen_var_name "$name")
		filter="-e '/^\.$/d;'"
		[ "x$dir" = "x." ] || filter="$filter -e '/^$(escape_dir "$dir")$/d;'"
		out_pat="$(cut -d: -f2 "$INDEX" | eval "sed $filter -e 's|$|/%|'" | tr '\n' ' ' | sed -e 's| \+$||')"

		if [ "x$dir" = "x." ]; then
			# root
			files_cmd="\$(GO_FILES)"
			files_cmd="\$(filter-out $out_pat, $files_cmd)"
		else
			files_cmd="\$(filter $dir/%, \$(GO_FILES))"
			files_cmd="\$(filter-out $out_pat, $files_cmd)"
			files_cmd="\$(patsubst $dir/%,%,$files_cmd)"
		fi

		cat <<-EOT
		$files$TAB=$TAB$files_cmd
		EOT
	done < "$INDEX" | column -t -s "$TAB" -o " "
}

gen_make_targets() {
	local cmd="$1" name="$2" dir="$3" mod="$4" deps="$5"
	local call= callu= callx=
	local depsx= cmdx=
	local sequential=

	# default calls
	case "$cmd" in
	tidy)
		# unconditional
		callu="\$(GO) mod tidy"

		# go vet and revive only if there are .go files
		#
		call="$(cat <<-EOT | packed
		\$(GO) vet ./...
		\$(REVIVE) \$(REVIVE_RUN_ARGS) ./...
		EOT
		)"

		depsx="fmt \$(REVIVE)"
		;;
	up)
		call="\$(GO) get -u -v ./...
\$(GO) mod tidy"
		;;
	test)
		call="\$(GO) $cmd ./..."
		;;
	*)
		call="\$(GO) $cmd -v ./..."
		;;
	esac

	case "$cmd" in
	build|test)
		sequential=true ;;
	*)
		sequential=false ;;
	esac

		# cd $dir
		if [ "." = "$dir" ]; then
			# root
			cd=
		else
			cd="cd '$dir'; "
		fi

		if [ "$name" = root ]; then
			# special case
			case "$cmd" in
			get)
				cmdx="get -tags tools"
				;;
			up)
				cmdx="get -tags tools -u"
				;;
			*)
				cmdx=
				;;
			esac

			[ -z "$cmdx" ] || cmdx="\$(GO) $cmdx -v ./..."

			case "$cmd" in
			up)
				# unconditional because of the tools
				callu="$cmdx
\$(GO) mod tidy
$(gen_install_tools)"
				;;
			get)
				# unconditional because of the tools
				callu="$cmdx
$(gen_install_tools)"
				;;
			*)
				callx="$call"
				;;
			esac
		else
			callx="$call"
		fi

		if [ "build" = "$cmd" ]; then
			# special build flags for cmd/*
			#
			callx="$(cat <<-EOL | packed_oneline
			set -e
			MOD="\$\$(\$(GO) list -f '{{.ImportPath}}' ./...)"
			if echo "\$\$MOD" | grep -q -e '.*/cmd/[^/]\+\$\$'; then
				\$(GO_BUILD_CMD) ./...
			elif [ -n "\$\$MOD" ]; then
				\$(GO_BUILD) ./...
			fi
			EOL
			)"
		fi

		if [ "tidy" = "$cmd" ]; then
			# exclude submodules when running revive
			#
			exclude=$(gen_revive_exclude "$dir")
			if [ -n "$exclude" ]; then
				callx=$(echo "$callx" | sed -e "s;\(REVIVE)\);\1 $exclude;")
			fi
		fi

		if ! $sequential; then
			deps=
		fi

		files=GO_FILES_$(gen_var_name "$name")
		cat <<EOT

$cmd-$name:${deps:+ $(prefixed $cmd $deps)}${depsx:+ | $depsx} ; \$(info \$(M) $cmd: $name)
EOT
	if [ -n "$callu" ]; then
		# unconditionally
		echo "$callu" | sed -e "/^$/d;" -e "s|^|\t\$(Q) $cd|"
	fi
	if [ -n "$callx" ]; then
		# only if there are files
		echo "ifneq (\$($files),)"
		echo "$callx" | sed -e "/^$/d;" -e "s|^|\t\$(Q) $cd|"
		echo "endif"
	fi
}

gen_files_lists

for cmd in $COMMANDS; do
	all="$(prefixed $cmd $PROJECTS)"
	depsx=

	cat <<EOT

.PHONY: $cmd $all
$cmd: $all
EOT

	while IFS=: read name dir mod deps; do
		deps=$(echo "$deps" | tr ',' ' ')

		gen_make_targets "$cmd" "$name" "$dir" "$mod" "$deps"
	done < "$INDEX"
done

for x in $PROJECTS; do
	cat <<EOT

$x: $(suffixed $x get build tidy)
EOT
done
