#! /usr/bin/env bash

# A function to generate formatted .md files
write_to_file() {
    local cmd="$1"
    local file="$2"
    local program="$3"

    # Remove first line of cmd to get rid of commit specific numbers.
    cmd=${cmd#*$'\n'}

    # We need to add the header and the backticks to create the code block.
    printf "# %s\n\n\`\`\`\n%s\n\`\`\`" "$program" "$cmd" > "$file"
}

# Check if a lighthouse binary exists in the current branch.
# -f means check if the file exists, to see all options, type "bash test" in a terminal
release=./target/release/lighthouse
debug=./target/debug/lighthouse

if [[ -f "$release" ]]; then
    CMD="$release"
elif [[ -f "$debug" ]]; then
    CMD="$debug"
else
    # No binary exists, build it.
    cargo build --locked
    CMD="$debug"
fi

# Store all help strings in variables.
general_cli=$($CMD --help)
bn_cli=$($CMD bn --help)
vc_cli=$($CMD vc --help)
vm_cli_create=$($CMD vm create --help)
vm_cli_import=$($CMD vm import --help)
vm_cli_move=$($CMD vm move --help)

general=./help_general.md
bn=./help_bn.md
vc=./help_vc.md
am=./help_am.md
vm_create=./help_vm_create.md
vm_import=./help_vm_import.md
vm_move=./help_vm_move.md

# create .md files
write_to_file "$general_cli" "$general" "Lighthouse General Commands"
write_to_file "$bn_cli" "$bn" "Beacon Node"
write_to_file "$vc_cli" "$vc" "Validator Client"
write_to_file "$vm_cli_create" "$vm_create" "Validator Manager Create"
write_to_file "$vm_cli_import" "$vm_import" "Validator Manager Import"
write_to_file "$vm_cli_move" "$vm_move" "Validator Manager Move"

#input 1 = $1 = files; input 2 = $2 = new files
files=(./book/src/help_general.md ./book/src/help_bn.md ./book/src/help_vc.md ./book/src/help_vm_create.md ./book/src/help_vm_import.md ./book/src/help_vm_move.md)
new_files=($general $bn $vc $vm_create $vm_import $vm_move)

# function to check
check() {
    local file="$1"
    local new_file="$2"
    
if [[ -f $file ]]; then # check for existence of file 
    diff=$(diff $file $new_file)
else
    cp $new_file $file
    changes=true
    echo "$file is not found, it has just been created"
fi

if [[ -z $diff ]]; then # check for difference 
    return 1 # exit a function (i.e., do nothing)
else
    cp $new_file $file
    changes=true
    echo "$file has been updated"
fi
}

# define changes as false
changes=false
# call check function to check for each help file
check ${files[0]} ${new_files[0]}
check ${files[1]} ${new_files[1]}
check ${files[2]} ${new_files[2]}
check ${files[3]} ${new_files[3]}
check ${files[4]} ${new_files[4]}
check ${files[5]} ${new_files[5]}

# remove help files
rm -f help_general.md help_bn.md help_vc.md help_am.md help_vm_create.md help_vm_import.md help_mv_move.md

# only exit at the very end
if [[ $changes == true ]]; then
    echo "Exiting with error to indicate changes occurred..."
    exit 1
else
    echo "CLI parameters are up to date."
    exit 0
fi
