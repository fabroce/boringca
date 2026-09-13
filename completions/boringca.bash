# bash completion for boringca
#
# Hand-written, no dependency on the `bash-completion` package's helper
# functions so it works in a plain bash too. The Debian package installs
# this file automatically (see debian/boringca.bash-completion); on any
# other system, drop it into /usr/share/bash-completion/completions/boringca
# or source it straight from your shell startup file, e.g.:
#
#   echo 'eval "$(cat completions/boringca.bash)"' >> ~/.bashrc

_boringca() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local subcommands="init issue install-trust help"

    # Find the subcommand, i.e. the first word after "boringca" that isn't
    # itself an option -- everything else (including the quick
    # "boringca <name>" path, which has no keyword of its own) falls
    # through to issue's options.
    local cmd=""
    local i
    for (( i=1; i<COMP_CWORD; i++ )); do
        case "${COMP_WORDS[i]}" in
            -*) ;;
            *) cmd="${COMP_WORDS[i]}"; break ;;
        esac
    done

    # A flag that expects a value: offer no completions for its argument
    # (paths, names, ... aren't worth guessing) except --dir, where a
    # directory completion is actually useful.
    case "$prev" in
        --dir)
            compopt -o dirnames 2>/dev/null
            COMPREPLY=( $(compgen -d -- "$cur") )
            return
            ;;
        --cn|--san|--days)
            COMPREPLY=()
            return
            ;;
    esac

    local opts
    case "$cmd" in
        init) opts="--cn --days --dir --force" ;;
        issue) opts="--cn --san --server --client --both --days --dir" ;;
        install-trust) opts="--dir" ;;
        "") opts="$subcommands -h --help" ;;
        *) opts="--cn --san --server --client --both --days --dir" ;;
    esac

    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
}
complete -F _boringca boringca
