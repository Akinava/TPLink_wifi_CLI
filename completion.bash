# Bash-обёртка и автодополнение для tplink_ac.py
#
# Подключить (разово в текущей сессии или строкой в ~/.bashrc):
#   source /home/lis/Projects/wifi_access/completion.bash
#
# После этого доступна команда `tplink-ac` с автодополнением по TAB:
#   tplink-ac <TAB>            -> list add del status enable disable mode
#   tplink-ac mode <TAB>       -> blacklist whitelist
#   tplink-ac add -t <TAB>     -> pc phone pad other
#   tplink-ac list -l <TAB>    -> blacklist whitelist

# Каталог проекта (определяется относительно этого файла)
_TPLINK_AC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

tplink-ac() {
    "$_TPLINK_AC_DIR/bin/python" "$_TPLINK_AC_DIR/src/tplink_ac.py" "$@"
}

_tplink_ac_complete() {
    local cur prev opts actions i seen_action
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    actions="list add del status enable disable mode"
    opts="-m --mac -n --name -t --type -l --list --host --password --debug -h --help"

    # значения для опций и для команды mode
    case "$prev" in
        mode)            COMPREPLY=($(compgen -W "blacklist whitelist" -- "$cur")); return;;
        -l|--list)       COMPREPLY=($(compgen -W "blacklist whitelist" -- "$cur")); return;;
        -t|--type)       COMPREPLY=($(compgen -W "pc phone pad other" -- "$cur")); return;;
        -m|--mac|-n|--name|--host|--password) return;;  # свободный ввод
    esac

    # опции
    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$opts" -- "$cur")); return
    fi

    # первая позиционная — команда (действие)
    seen_action=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            list|add|del|status|enable|disable|mode) seen_action="${COMP_WORDS[i]}"; break;;
        esac
    done
    if [[ -z "$seen_action" ]]; then
        COMPREPLY=($(compgen -W "$actions" -- "$cur"))
    fi
}

# Регистрируем и для обёртки, и для прямого вызова скрипта по имени файла
complete -F _tplink_ac_complete tplink-ac
complete -F _tplink_ac_complete tplink_ac.py
