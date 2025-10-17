#! /bin/bash

tmux display-menu \
	"split vertical" v "split -v" \
	"split horizontal" h "split -h" \
	"terminal" t "switch-client -t pwnenv-terminal" \
	"debugger" d "switch-client -t pwnenv-debugger" \
	"editor" e "switch-client -t pwnenv-editor"

tmux set -g mouse on
