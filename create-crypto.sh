#!/bin/bash

trap "early_exit" INT TERM

if [ "$1" = "debug" ]; then
	debug_me="true"
else
	debug_me="false"
fi

# COLOR DEFINITIONS ==========================================================

# Reset
Color_Off='\033[0m'       # Text Reset

# Regular Colors
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White

# Bold
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue
BPurple='\033[1;35m'      # Purple
BCyan='\033[1;36m'        # Cyan
BWhite='\033[1;37m'       # White

# Underline
UBlack='\033[4;30m'       # Black
URed='\033[4;31m'         # Red
UGreen='\033[4;32m'       # Green
UYellow='\033[4;33m'      # Yellow
UBlue='\033[4;34m'        # Blue
UPurple='\033[4;35m'      # Purple
UCyan='\033[4;36m'        # Cyan
UWhite='\033[4;37m'       # White

# Background
On_Black='\033[40m'       # Black
On_Red='\033[41m'         # Red
On_Green='\033[42m'       # Green
On_Yellow='\033[43m'      # Yellow
On_Blue='\033[44m'        # Blue
On_Purple='\033[45m'      # Purple
On_Cyan='\033[46m'        # Cyan
On_White='\033[47m'       # White

# High Intensity
IBlack='\033[0;90m'       # Black
IRed='\033[0;91m'         # Red
IGreen='\033[0;92m'       # Green
IYellow='\033[0;93m'      # Yellow
IBlue='\033[0;94m'        # Blue
IPurple='\033[0;95m'      # Purple
ICyan='\033[0;96m'        # Cyan
IWhite='\033[0;97m'       # White

# Bold High Intensity
BIBlack='\033[1;90m'      # Black
BIRed='\033[1;91m'        # Red
BIGreen='\033[1;92m'      # Green
BIYellow='\033[1;93m'     # Yellow
BIBlue='\033[1;94m'       # Blue
BIPurple='\033[1;95m'     # Purple
BICyan='\033[1;96m'       # Cyan
BIWhite='\033[1;97m'      # White

# High Intensity backgrounds
On_IBlack='\033[0;100m'   # Black
On_IRed='\033[0;101m'     # Red
On_IGreen='\033[0;102m'   # Green
On_IYellow='\033[0;103m'  # Yellow
On_IBlue='\033[0;104m'    # Blue
On_IPurple='\033[0;105m'  # Purple
On_ICyan='\033[0;106m'    # Cyan
On_IWhite='\033[0;107m'   # White


# DEFAULTS & CONSTANTS =======================================================

# make "false" and "true" immutable
declare -ir false=0 true=1

# get the "home" of this script, no matter where this is executed from
# SCRIPT_DIR=$(dirname "$(readlink -f "$0")")  # this required coreutils
SCRIPT_DIR=$(exec 2>/dev/null;cd -- $(dirname "$0"); unset PWD; /usr/bin/pwd || /bin/pwd || pwd)

# purge sudo password cache (if set previously), and reset other sudo related variables
sudo -k
SUDOPWD=
# check if the user is allowed to execute sudo without a password
if sudo -n true 2>/dev/null; then
	is_sudo=1
else
	is_sudo=0
fi

# assume either execution as, or creating vault for oneself (as an unprivileged user)
vault_fileop_sudoreq="false"
mount_fileop_sudoreq="false"
command_fileop_sudoreq="false"

# who *am* I?
# todo: maybe use login_user for suggests?
login_user=$(logname 2>/dev/null || echo ${SUDO_USER:-${USER}})
current_user=$(whoami)
# am I root??
if [ "$EUID" -eq 0 ]; then
	im_root="true"
else
	im_root="false"
fi

# starting out as undefined CRYPTPWD
CRYPTPWD=

# Define the dialog exit status codes
: ${DIALOG_OK=0}
: ${DIALOG_CANCEL=1}

# get platform/package manager
declare -A osInfo;
osInfo[/etc/redhat-release]=yum
osInfo[/etc/debian_version]=apt-get

package_manager=""
for f in ${!osInfo[@]}
do
	if [[ -f $f ]]; then
		package_manager=${osInfo[$f]}
    fi
done

if [ "$package_manager" = "" ]; then
	package_manager="[your package manager]"
fi


# FUNCTIONS ==================================================================

# exists for commands
exists() {
	command -v "$1" >/dev/null 2>&1
}

yesno() {
	# $1 is the retval (_ret)

	old_stty_cfg=$(stty -g)
	stty raw -echo
	answer=$( while ! head -c 1 | grep -i '[yn]' ;do true ;done )
	stty $old_stty_cfg

	if echo "$answer" | grep -iq "^n" ; then
		_ret="no"
	else
		_ret="yes"
	fi

	eval "$1=${_ret}"
}

validate_sudopwd() {
	if [ "$is_sudo" = "1" ]; then
		break
	else
		dialog --title "ERROR" --msgbox "\nINCORRECT SUDO PASSWORD!\n\nPlease try again!" 9 30
	fi
}

get_sudo_pwd() {
	# get password
	while true; do
		SUDOPWD=$(dialog --title "Enter sudo password" --insecure --passwordbox "\nThis script requires sudo access. Please enter your sudo password (your login password) to be used for the elevated script operations. The password will be cached internally by this script, but depending on your system policy, you may be re-prompted for sudo password later.\n\nNOTE: If your username is allowed to execute sudo without a password, enter an empty password above (i.e. simply press OK).\n\n" 18 70  2>&1 > /dev/tty)
		_ret=$?

		# first clear sudo password cache
		sudo -k

		# first check if the user is allowed to execute sudo without a password
		if sudo -n true 2>/dev/null; then
			is_sudo=1
		else
			# that didn't work.. now let's see if sudo is allowed with the cached password
			echo ${SUDOPWD} | sudo -S -v &> /dev/null

			if [ $? -ne 0 ]; then
				is_sudo=0
			else
				is_sudo=1
			fi
		fi

		# ok (proceed) / cancel
		# note: validate_sudopwd exits the while loop when pass
		case ${_ret} in
			0)
				validate_sudopwd
				;;
			1)
				early_exit
				;;
		esac
	done
}

# sudo for system operations
# use the locally cached sudo password if sudo doesn't cache the password by policy (or if it has expired)
sudoit() {
	# $1 is the retval (_ret)
	# $2 (and ...) are the commands/args to execute with sudo

	if [ "$im_root" = "false" ]; then
		if sudo -n true 2>/dev/null; then 
			sudo "${@:2}" 2>/dev/null
			_ret=$?
		else
			echo ${SUDOPWD} | sudo -S "${@:2}" 2>/dev/null
			_ret=${PIPESTATUS[1]}
		fi
	else
		# running as root, no sudo needed
		eval "${@:2}" 2>/dev/null
		_ret=$?
	fi

	eval "$1=${_ret}"
}

# always sudo because executing as a different user
# use the locally cached sudo password if sudo doesn't
# cache the password by policy (or if it has expired)
sudoitas() {
	# $1 is the retval (_ret)
	# $2 is user to run as sudo (sudo_user)

	sudo_user=$2
	if sudo -n true 2>/dev/null; then 
		sudo -u $sudo_user "${@:3}" 2>/dev/null
		_ret=$?
	else
		echo ${SUDOPWD} | sudo -S -u $sudo_user "${@:3}" 2>/dev/null
		_ret=${PIPESTATUS[1]}
	fi

	eval "$1=${_ret}"
}

# find the first existing parent of the given dir
find_existing_parent() {
	# $1 is the retval (_ret)
	# $2 is the path for which we're finding an existing parent

	pathname="$2"

	if [ -d "$pathname" ]; then
		eval "$1=$2"  
	else
		IFS='/' read -r -a p <<<"${pathname#/}"

		pa=""
		max="${#p[@]}"
		# record number of segments in the result array
		fep_result[3]=$max
		i=0
		while (( i<"$max" )); do
			paprev=$pa
			pa="$pa/${p[i++]}"
			if [[ ! -e $pa ]]; then
				# record first existing parent in the result array
				fep_result[1]=$paprev
				# record first created segment in the result array
				fep_result[2]=$pa
				eval "$1=$paprev"
				break
			fi
		done
	fi
}

# who owns the given dir
find_dir_owner() {
	# $1 is the retval (_ret)
	# $2 is the path whose owner we're looking

	dirowner=$(ls -ld $2 | awk '{print $3}')
	eval "$1=$dirowner"
}

# is the given path an ancestor to the second path (paths need not exist)
dir_is_ancestor() {
	# $1 is the retval (_ret)
	# $2 is the base path (e.g. the potential ancestor)
	# $3 is the new path (e.g. the potential child)

	basepath="$2"
	newpath="$3"

	is_ancestor="false"
	if [[ "$newpath" =~ ^(${basepath//\//\\\/})([^/]*)(.*)$ ]]; then

		if [ "${BASH_REMATCH[1]}" != "" ] && # i.e. basepath is matched
			[ "${BASH_REMATCH[2]}" = "" ] &&  # i.e. it is the exact base path (the last component of base path does not continue before the end/slash)
			[ "${BASH_REMATCH[3]}" != "" ]; then  # i.e. a deeper path exits; the basepath is an ancestor for the newpath!

			is_ancestor="true"
		fi
	fi

	if [ "${is_ancestor}" = "true" ]; then
		eval "$1=true"
	else
		eval "$1=false"
	fi

}

# find the first available directory name with an appended ordinal;
# start from 2 (as if the matching name already exists, it's
# essentially the first one.
get_first_available_dir() {
	# $1 is the retval (_ret)
	# $2 is the dir to check
	# $3 modifies the check behavior:
	#   any: offer first available [named] directory (including existing if not mounted); new if no directory exists
	#   any_empty: same as above, except the directory must be empty
	#   new (or anything underfined): always increment from existing

	local dir_to_check=$2
	local checktype=$3
	local dir_to_check_mounted=""

	if [ ! -e ${dir_to_check} ]; then
		# use the name as-is (the named directory gets created)
		n=""

	else
		check_mounted dir_to_check_mounted ${dir_to_check}

		if [ "${checktype}" = "any" ] &&
			[ -d "${dir_to_check}" ] &&
			[ "${dir_to_check_mounted}" = "false" ]; then

			# "ANY": dir exists and is not mounted -> use it as-is
			n=""
		elif [ "${checktype}" = "any_empty" ] &&
			[ -d "${dir_to_check}" ] &&
			[ ! "$(ls -A $dir_to_check)" ] &&
			[ "${dir_to_check_mounted}" = "false" ]; then

			# "ANY_EMPTY": dir exists, is empty, and is not mounted -> use as-is
			n=""
		elif [ "${checktype}" = "any_empty" ] && 
			[ ! -d "${dir_to_check}" ]; then

			# "ANY_EMPTY": dir does not exist (hence it is empty, and is not mounted) -> use as-is
			n="" 
		elif [ "${checktype}" = "any" ] &&
			[ -d "${dir_to_check}" ] &&
			[ "${dir_to_check_mounted}" = "true" ]; then

			# "ANY": dir exists but is mounted -> increment!
			n=2
		elif [ "${checktype}" = "any_empty" ] &&
			[ -d "${dir_to_check}" ] &&
			[[ (! "$(ls -A $dir_to_check)") || ("${dir_to_check_mounted}" = "true") ]]; then

			# "ANY_EMPTY": dir exists, but either is not empty or is mounted -> increment!
			n=2
		else # this serves "any" that wasn't matched, as well as "new"
			# dir or file of the same name exists and "new" is requested -> increment!
			n=2
		fi

		if [ "${n}" = "2" ]; then
			local check_for_mount=""
			local dir_is_mounted="false"

			while true; do
				check_for_mount="${dir_to_check}${n}"
				if [ -d "${check_for_mount}" ]; then
					check_mounted dir_is_mounted ${check_for_mount}
				fi
				if [ ! -e "${check_for_mount}" ] ||
					[ "${dir_is_mounted}" = "false" ]; then
					break
				fi

				# prepare for the next iteration
				dir_is_mounted="false"
				((n++))

			done
		fi
	fi

	fad[1]=${dir_to_check}${n}
	fad[2]=$n
	eval "$1=${fad[1]}"
}

# find the first available filename with an appended ordinal;
# start from 2 (as if the matching name already exists, it's
# essentially the first one.
get_first_available_file() {
	# $1 is the retval (_ret)
	# $2 is the file to check
	# $3 is the directory to check in (no recursion)

	local file_to_check=$2
	local dir_to_check_in=$3

	local file_fqfn="${dir_to_check_in}/${file_to_check}"

	if [ ! -e "${file_fqfn}" ]; then
		n=""
	else
		n=2

		while true; do
			file_fqfn="${dir_to_check_in}/${file_to_check}${n}"
			if [ ! -e "${file_fqfn}" ]; then
				break
			fi

			# prepare for the next iteration
			((n++))
		done

	fi

	faf[1]=${file_to_check}${n}
	faf[2]=$n
	eval "$1=${faf[1]}"
}

# check mountpath against mounts in /proc/mounts
check_mounted() {
	# $1 is the retval (_ret)
	# $2 is the path we're checking for active mountpoint

	if grep -qsE "^[^ ]+ $2" /proc/mounts; then
		response="true"
	else
		response="false"
	fi
	eval "$1=$response"
}

# revert made changes (such as after an partially completed setup)
cleanup() {
	echo
	if [ "$1" = "interrupt" ]; then
		echo -e "${Black}${On_Red}SCRIPT INTERRUPTED${Color_Off}"  
	fi
	echo -e "${BIRed}Cleaning up...${Color_Off}"  

	check_mounted mount_in_proc $MOUNTPOINT
	if [ "${mount_in_proc}" = "true" ]; then
		# cryptovault is currently mounted.. start by attempting to unmount

		# export zfs pool, umount ext4 fs
		dismounted="false"
		if [ "$CRYPTOVAULT_FS" = "zfs" ]; then

			#export zfs
			while [ "$dismounted" = "false" ]; do
				sudoit _ret zpool export $zpool_id > /dev/null 2>&1
				if [ ${_ret} -ne 0 ]; then
					if ! sudo -n true 2>/dev/null; then 
						echo -e "${IYellow}This operation may require you to re-enter your sudo password below:${Color_Off}"
						echo
					fi 
					echo "Unable to unmount the crypto vault; the device is busy. Free the device (such as make sure you aren't currently cd'd in the crypto vault, or that you don't have files open from the vault), and try again."
					echo
					echo "The following process(es) hold the mount:"
					x=(); for a in $(mount | cut -d' ' -f3); do test -e "$a" || x+=("-e$a"); done
					sudo lsof "${x[@]}" -f -- ${MOUNTPOINT}
					echo
					read -p "Press any key to retry unmount! " -n1 -s
				else
					dismounted="true"
				fi
			done
			echo "zfs pool exported (file system dismounted) from mountpoint ${MOUNTPOINT}."

		else

			# unmount ext4
			while [ "$dismounted" = "false" ]; do
				sudoit _ret umount ${MOUNTPOINT} > /dev/null 2>&1
				if [ ${_ret} -ne 0 ]; then
					if ! sudo -n true 2>/dev/null; then 
						echo -e "${IYellow}This operation may require you to re-enter your sudo password below:${Color_Off}"
						echo
					fi 
					echo "Unable to unmount the crypto vault; the device is busy. Free the device (such as make sure you aren't currently cd'd in the crypto vault, or that you don't have files open from the vault), and try again."
					echo
					echo "The following process(es) hold the mount:"
					x=(); for a in $(mount | cut -d' ' -f3); do test -e "$a" || x+=("-e$a"); done
					sudo lsof "${x[@]}" -f -- ${MOUNTPOINT}
					echo
					read -p "Press any key to retry unmount! " -n1 -s
				else
					dismounted="true"
				fi
			done
			echo "ext4 filesystem unmounted from mountpoint ${MOUNTPOINT}."
		fi  

	else
		# crypto vault is not mounted at this point (perhaps it never was as this is cleanup)
		dismounted="true"
	fi

	# remove mapped disk if present
	if [ -b /dev/mapper/${CRYPTOVAULT_LABEL} ]; then
		sudoit _ret cryptsetup luksClose /dev/mapper/${CRYPTOVAULT_LABEL}
		if [ ${_ret} -ne 0 ]; then
			echo "Unable to remove the mapped disk \"/dev/mapper/${CRYPTOVAULT_LABEL}\""
		else
			echo "Mapped device /dev/mapper/${CRYPTOVAULT_LABEL} removed."    
		fi
	fi

	if ! sudo -n true 2>/dev/null; then 
		echo -e "${IYellow}This operation may require you to re-enter your sudo password below:${Color_Off}"
	fi 
	# acquire a free loop device
	loopdev2del=$(sudo losetup --raw | grep ${VAULTFILE_FQFN} | awk '{print $1}')
	# delete the assigned loop device if present
	if [ "$loopdev2del" != "" ]; then
		sudoit _ret losetup -d $loopdev2del > /dev/null 2>&1
		if [ ${_ret} -ne 0 ]; then
			echo "Unable to remove the assigned loop device ${loopdev2del}."
		else
			echo "Assigned loop device $loopdev2del removed."
		fi
	fi

	if [ "$1" = "nodelete" ]; then
		echo
		echo "Cleanup complete."
		exit_info  # exits with status 0

	else
		# we're here either via trapped INT or TERM, or because of user-selected cancellation

		# remove the vault file 
		if [ -f $VAULTFILE_FQFN  ]; then

			if [ "$vault_fileop_sudoreq" = "false" ]; then
				rm -f "$VAULTFILE_FQFN"
				_ret=$?
			else
				sudoit _ret rm -f "$VAULTFILE_FQFN"
			fi

			if [ ${_ret} -ne 0 ]; then
				echo "Unable to remove the vault file \"$VAULTFILE_FQFN\"."
			else
				echo "Vault file \"$CRYPTOVAULT_LABEL\" removed."
			fi
		else
			echo "There was no vault file to remove."
		fi

		# remove the vault directory
		if [ ! -d $VAULTFILE_HOME ]; then
			echo "There was no vault directory to remove."
		elif [ -d $VAULTFILE_HOME ] &&
			[ "$vaultpath_exists" = "false" ] &&
			[ ! "$(ls -A $VAULTFILE_HOME)" ]; then

			if [ "$vault_fileop_sudoreq" = "false" ]; then
				rm -rf "$vaultpath_first_created"
				_ret=$?
			else
				sudoit _ret rm -rf "$vaultpath_first_created"
			fi

			if [ ${_ret} -ne 0 ]; then
				echo "Unable to remove the vault directory \"$VAULTFILE_HOME\"."
			else
				echo "Vault directory \"$VAULTFILE_HOME\" removed (it was created during this process, and was now empty)."
			fi

		else
			echo "Vault directory was not created by this process. Leaving it intact."
		fi

		if  [ ! -d $MOUNTPOINT ]; then
			echo "There was no mountpoint directory to remove."
		elif [ -d $MOUNTPOINT ] &&
			[ "$mountpoint_exists" = "false" ] &&
			[ ! "$(ls -A $MOUNTPOINT)" ]; then

			if [ "$vault_fileop_sudoreq" = "false" ]; then
				rm -rf "$mountpath_first_created"
				_ret=$?
			else
				sudoit _ret rm -rf "$mountpath_first_created"
			fi

			if [ ${_ret} -ne 0 ]; then
				echo "Unable to remove the mountpoint directory \"$MOUNTPOINT\"."
			else
				echo "Mountpoint directory \"$MOUNTPOINT\" removed (it was created during this process, and was empty)."
			fi

		else
			echo "Mountpoint directory was not created by this process. Leaving it intact."
		fi

		# remove the vault command scripts 
		total_scripts_present=0
		total_scripts_removed=0
		scripts_to_remove=(
			${CRYPTOVAULT_COMMANDDIR}/mount-${CRYPTOVAULT_LABEL}
			${CRYPTOVAULT_COMMANDDIR}/umount-${CRYPTOVAULT_LABEL}
			${CRYPTOVAULT_COMMANDDIR}/util-${CRYPTOVAULT_LABEL}
		)

		for script in "${scripts_to_remove[@]}"
		do

			if [ -f ${script} ]; then
				((total_scripts_present++))

				if [ "$command_fileop_sudoreq" = "false" ]; then
					rm -f "${script}"
					_ret=$?
				else
					sudoit _ret rm -f "${script}"
				fi
			fi

			if [ ${_ret} -eq 0 ]; then
				((total_scripts_removed++))
			fi

		done

		if [ $total_scripts_present -gt $total_scripts_removed ]; then
			echo "Unable to remove all vault command scripts."
		elif [ $total_scripts_present -eq $total_scripts_removed ]; then
			echo "Vault command scripts removed."
		else
			echo "There were no vault command script to remove."
		fi

		# remove the vault command script directory
		if [ ! -d $CRYPTOVAULT_COMMANDDIR ]; then
			echo "There was no command script directory to remove."
		elif [ -d $CRYPTOVAULT_COMMANDDIR ] &&
			[ "$commanddir_exists" = "false" ] &&
			[ ! "$(ls -A $CRYPTOVAULT_COMMANDDIR)" ]; then

			if [ "$command_fileop_sudoreq" = "false" ]; then
				rm -rf "$commanddir_first_created"
				_ret=$?
			else
				sudoit _ret rm -rf "$commanddir_first_created"
			fi

			if [ ${_ret} -ne 0 ]; then
				echo "Unable to remove the command script directory \"$CRYPTOVAULT_COMMANDDIR\"."
			else
				echo "Command script directory \"$CRYPTOVAULT_COMMANDDIR\" removed (it was created during this process, and was now empty)."
			fi

		else
			echo "Command script directory was not created by this process. Leaving it intact."
		fi

		echo
		echo "Cleanup complete. Exiting."
		echo

		exit 1

	fi
}

# exit before the action begins
early_exit() {
	dialog --title "Confirm script termination" --yesno "\nAre you sure you want to exit the crypt vault creation process?" 8 70
	_ret=$?

	case ${_ret} in
		0)
			clear && echo -e "\nCrypto disk creation cancelled.\n\n" && exit 1
			;;
		1)
			;;
	esac
}

# clean exit
exit_info() {
	echo
	echo "Please use the \"mount-${CRYPTOVAULT_LABEL}\" and \"umount-${CRYPTOVAULT_LABEL}\" command scripts at ${CRYPTOVAULT_COMMANDDIR} to mount and dismount your newly created crypto vault \"${CRYPTOVAULT_LABEL}\"."
	echo

	exit 0
}


# PREREQS CHECKS =============================================================

if [[ "$package_manager" != "apt-get" ]] &&
	[[ "$package_manager" != "yum" ]]; then

	printf "NOTE: Only Debian/Ubuntu and RedHat/CentOS variants are officially supported by this script!\nContinue anyway? (y/n)?"
	yesno _ret
	if [ "$_ret" = "no" ]; then
		exit 1
	fi
fi

if ! exists dialog ; then
	if [[ "$package_manager" == "apt-get" ]] ||
		[[ "$package_manager" == "yum" ]]; then

		printf "\n\n*************************************************************************************************\n\
This script requires dialog. Install it first with 'sudo $package_manager install dialog', then try again!\n\
*************************************************************************************************\n\n"

	else

		printf "\n\n*************************************************************************************************\n\
This script requires dialog. Install it first with your package manager, then try again!\n
*************************************************************************************************\n\n"

	fi

	exit 1
fi

if [ "$EUID" -ne 0 ]; then
	if [ $is_sudo -eq 0 ]; then
		get_sudo_pwd
	fi
else
	im_root="true"
fi

CRYPTSETUP=$(sudo which cryptsetup)
if [ $? -ne 0 ]; then

	echo
	echo -n "This script requires 'cryptsetup'. Can I install it? (y/n)? "
	yesno _ret
	if [ "$_ret" = "yes" ]; then
		if [[ "$package_manager" == "apt-get" ]]; then
			sudoit _ret apt-get -y install cryptsetup
		elif [[ "$package_manager" == "yum" ]]; then
			sudoit _ret yum -y install cryptsetup
		fi

		if [ ${_ret} -eq 0 ]; then
			printf "\ncryptsetup was installed; continuing...\n\n"
		else
			printf "\ncryptsetup installation was unsuccessful. Unable to continue. Please try installing manually, then try again.\n\n"
			exit 1
		fi

	else 
		printf "\n\n*********************************************************************************************************\n\
This script requires cryptsetup. Install it first with 'sudo $package_manager install cryptsetup', then try again!\n\
*********************************************************************************************************\n\n"
	exit 1
	fi
fi


# MAIN LOGIC: QUERY VAULT PARAMETERS =========================================

# pre-increment suggested paths so that the label and the suggeted mountpoint
# numbers aren't out of sync (i.e. "/mnt/cryptovault2" vs. "/var/vaultfiles/cryptovault3")

if [ "$current_user" = "root" ]; then
	initial_suggested_vaulthome_dir="/var/vaultfiles"
	initial_suggested_vault_label="cryptovault"
	initial_suggested_vaultfile_fqfn="${initial_suggested_vaulthome_dir}/${initial_suggested_vault_label}"
	initial_suggested_mountpoint_dir="/mnt/cryptovault"
else
	initial_suggested_vaulthome_dir="${HOME}/vaultfiles"
	initial_suggested_vault_label="${current_user}-cryptovault"
	initial_suggested_vaultfile_fqfn="${initial_suggested_vaulthome_dir}/${initial_suggested_vault_label}"
	initial_suggested_mountpoint_dir="${HOME}/mnt/cryptovault"
fi

if [ -e $initial_suggested_vaultfile_fqfn ] ||
	[ -e $initial_suggested_mountpoint_dir ]; then

	suggested_n=2
	while true; do
		testing_vaultfile_fqfn="${initial_suggested_vaultfile_fqfn}${suggested_n}"
		testing_mountpoint_dir="${initial_suggested_mountpoint_dir}${suggested_n}"
		
		if [ -e "${testing_vaultfile_fqfn}" ] ||
			[ -e "${testing_mountpoint_dir}" ]; then

			((++suggested_n))
		else
			initial_suggested_vault_label="${initial_suggested_vault_label}${suggested_n}"
			initial_suggested_mountpoint_dir="${initial_suggested_mountpoint_dir}${suggested_n}"
			break
		fi
	done
fi

# FILE SYSTEM SELECTION
while true; do
	SELECT_CRYPTO_FS=$(dialog --title "Select crypto vault file system" --radiolist "\nSelect the file system for the encrypted vault.\nZFS is recommended for multiple reasons.\n\n
NOTE: Highlight the choice with up/down arrow, select with SPACE." 16 55 2 \
            1 zfs on \
            2 ext4 off \
          2>&1 > /dev/tty)
	_ret=$?

	# ok (proceed) / cancel
	case ${_ret} in
		0)
			;;
		1)
			early_exit && continue
			;;
	esac

	if [ "$SELECT_CRYPTO_FS" = "1" ]; then
		CRYPTOVAULT_FS="zfs"

		ZFS=$(sudo which zfs)
		if [ $? -ne 0 ]; then

			echo
			echo -n "To use ZFS filesystem zfsutils-linux package is required. Can I install it? (y/n)? "
			yesno _ret
			if [ "$_ret" = "yes" ]; then
				if [[ "$package_manager" == "apt-get" ]]; then
					sudoit _ret apt-get -y install zfsutils-linux
				elif [[ "$package_manager" == "yum" ]]; then
					sudoit _ret yum -y install zfsutils-linux
				fi

				if [ ${_ret} -eq 0 ]; then
					printf "\nzfsutils-linux was installed; continuing...\n\n"
				else
					printf "\nzfsutils-linux installation was unsuccessful. Unable to continue. Please try installing it manually, then try again.\n\n"
					exit 1
				fi

			else 

				printf "\n\n**************************************************************************************************************************************\n\
To use ZFS filesystem zfsutils-linux package is required. Install it first with 'sudo $package_manager install zfsutils-linux', then try again!\
\n**************************************************************************************************************************************\n\n\n"

			exit 1
			fi
		fi
		break

	elif [ "$SELECT_CRYPTO_FS" = "2" ]; then
		CRYPTOVAULT_FS="ext4"
		break
	fi

done

# ENCRYPTION PASSWORD SELECTION
while true; do
	CRYPT_PASS_SEL_1=$(dialog --title "Enter encryption password" --insecure --passwordbox "\nEnter the passphrase you want the vault to be encrypted with.\n\n" 12 50  2>&1 > /dev/tty)
	_ret=$?

	# ok (proceed) / cancel
	case ${_ret} in
		0)
			;;
		1)
			early_exit && continue
			;;
	esac

	CRYPT_PASS_SEL_2=$(dialog --title "Repeat encryption password" --insecure --passwordbox "\nEnter again the passphrase you want the vault to be encrypted with.\n\n" 12 50 2>&1 > /dev/tty)
	_ret=$?

	# ok (proceed) / cancel
	case ${_ret} in
		0)
			;;
		1)
			early_exit && continue
			;;
	esac

	if [ "${CRYPT_PASS_SEL_1}" = "${CRYPT_PASS_SEL_2}" ]; then
		if [ "${CRYPT_PASS_SEL_1}" = "" ]; then
			dialog --title "ERROR" --msgbox "\nAn empty passphrase is not allowed!\n\nPlease try again!" 10 40
		else 
			CRYPTPWD=$CRYPT_PASS_SEL_1
			break
		fi
	else
		dialog --title "ERROR" --msgbox "\nPASSPHRASES DO NOT MATCH!!\n\nPlease try again!" 10 40
	fi
done


# VAULT SIZE SELECTION
while true; do
	CRYPTOVAULTSIZEINPUT=$(dialog --title "Enter desired crypto vault size" --inputbox "\nEnter the desired crypto vault size in\nmegabytes (MB) or gigabytes (GB).\n\nPlease be mindful of the available drive space.\n\n" 14 55 512MB 2>&1 > /dev/tty)
	_ret=$?

	# ok (proceed) / cancel
	case ${_ret} in
		0)
			;;
		1)
			early_exit && continue
			;;
	esac

	if [[ $CRYPTOVAULTSIZEINPUT =~ ^([0-9]+)[[:space:]]*(MB|Mb|mb|GB|Gb|gb)$ ]]; then
		VAULTSIZEVAL=${BASH_REMATCH[1]}
		VAULTSIZEUNIT=$(echo "${BASH_REMATCH[2]}" | awk '{print toupper($0)}')

		zfssizefault="false"
		if [ "$CRYPTOVAULT_FS" = "zfs" ] &&
			[ "$VAULTSIZEUNIT" = "MB" ] &&
			[ $VAULTSIZEVAL -lt 128 ]; then

			zfssizefault="true"
			dialog --title "ERROR" --msgbox "\nZFS filesystem requires minimum vault size of 128MB!" 8 60
		fi

		if [ "$zfssizefault" = "false" ]; then
			break
		fi
	else
		dialog --title "ERROR" --msgbox "\nUnacceptable crypto vault size!\n\nPlease enter the numeric size (integers only), followed by \"MB\" or \"GB\"!" 14 50
	fi
done

# VAULT FILE LOCATION
# $initial_suggested_vaulthome_dir comes from preincrement (double-checking here..)
get_first_available_dir suggested_vaulthome_dir $initial_suggested_vaulthome_dir "any"

if [ "$current_user" = "root" ]; then
	vaulthome_example="\nSuggested system-wide vault file location: $suggested_vaulthome_dir"
else
	vaulthome_example="\nSuggested vault file location: ${suggested_vaulthome_dir}"
fi

while true; do
	dialog --title "Vault file location selection" --msgbox "\nOn the next screen select the location where you want the vault file to be saved. 
If this is a system-wide vault, use a path, for example, under /var/ (such as /var/vaultfiles). For a personal vault, select a location under a home directory (e.g. /home/alice/vaultfiles).\n\n
NOTE: In this step you will select the directory where the vault file is saved. In the next step you will select the vault file name/label.\n\n
NOTE: Use Up/Dn [arrow] to move to move the selector, SPACE to copy selected directory to the edit line, and ENTER to accept the current path in the edit box. To move to subdir/parent, add/remove \"/\" after the directory name on the edit line.\n\n
NOTE: If a previously non-existing path is entered, the directory/directories will be created. To accept the suggested path, just hit Enter on the next screen..\n\n
${vaulthome_example}" 26 78

	VAULTFILE_HOME=$(dialog --title "Vault file location selection" --dselect ${suggested_vaulthome_dir} 16 60 2>&1 > /dev/tty)
	_ret=$?

	#remove slash from the end if there is one
	VAULTFILE_HOME=${VAULTFILE_HOME%/}
  
	case ${_ret} in
		0)
			;;
		1)
			early_exit && continue
			;;
	esac

	find_existing_parent vaultpath_existing_parent $VAULTFILE_HOME
	find_dir_owner vaultpath_owner ${vaultpath_existing_parent}
	# get this result array via a global set by find_existing_parent, called above
	vaultpath_first_created=${fep_result[2]}

	vaulthome_owner_info=""
	if [ "$current_user" != "$vaultpath_owner" ]; then
		if [ "$vaultpath_owner" = "root" ]; then
			vaulthome_owner_info="The selected location is a system location, and will be owned by the root user.\n\n"
		else
			vaulthome_owner_info="The selected location is owned by user \"$vaultpath_owner\", and the vault file will be made private to that user.\n\n"
		fi
	fi

	# since the target vault location is different from the current user, 
	# if this is not executed as root, sudo is required for the related filesystem operations
	if [ "$current_user" != "$vaultpath_owner" ] &&
		[ "$im_root" = "false" ]; then

		vault_fileop_sudoreq="true"
	else
		vault_fileop_sudoreq="false"
	fi

	path_creation_info=""
	vaultpath_exists="true"

	if [ ! -d "$VAULTFILE_HOME" ]; then
		path_creation_info="This directory does not exist; it will be created."
		vaultpath_exists="false"
	else
		path_creation_info="Using an existing directory."
	fi

	dialog --title "Confirm selected vault file location" --yesno "\nYou selected vault file location:\n\n${VAULTFILE_HOME}\n\n${path_creation_info}\n\n${vaulthome_owner_info}Is this what you want?" 14 70
	_ret=$?

	case ${_ret} in
		0)
			break
			;;
		1)
			;;
	esac

done

# VAULT LABEL/FILE NAME
# $initial_suggested_vault_label comes from preincrement (double-checking here with the selected home)
get_first_available_file suggested_vault_label $initial_suggested_vault_label $VAULTFILE_HOME
vaultlabel_example="\nSuggested vault label: ${suggested_vault_label}"

while true; do
	CRYPTOVAULT_LABEL_INPUT=$(dialog --title "Crypto Vault Label/File Name" --inputbox "\nEnter the desired crypto vault label (no spaces). It will also be used as the crypto vault file name.\n\n
NOTE: Since the crypto vaults are mapped through /dev/mapper system-wide (even when access is limited to a specific user), the label must be unique on the system. For user vaults, including the user's name in the vault name is recommended.\n\n
NOTE: To accept the default/suggestion, just hit ENTER\n" 17 70 "${suggested_vault_label}" 2>&1 > /dev/tty)
	_ret=$?

	# ok (proceed) / cancel
	case ${_ret} in
		0)
			;;
		1)
			early_exit && continue
			;;
	esac

	CRYPTOVAULT_LABEL=$(echo "${CRYPTOVAULT_LABEL_INPUT// /}")

	if [ "$CRYPTOVAULT_LABEL" = "" ] ||
		[[ $CRYPTOVAULT_LABEL =~ ^[_.=-]*$ ]]; then

		dialog --title "ERROR" --msgbox "Crypto vault file name cannot be empty, or contain only hyphens/underscores/spaces. Please select a valid name." 14 50

	else

		vaultname_conflict="false"
		mapper_conflict="false"
		for i in /dev/mapper/*; do
			thisbase=$(basename $i)
			if [ "$thisbase" = "$CRYPTOVAULT_LABEL" ]; then
				vaultname_conflict="true"
				mapper_conflict="true"
			fi
		done

		VAULTFILE_FQFN="${VAULTFILE_HOME}/${CRYPTOVAULT_LABEL}"

		if [ -e "${VAULTFILE_FQFN}" ]; then
			vaultname_conflict="true"
		fi  

		if [ "$vaultname_conflict" = "true" ]; then
			if [ "$mapper_conflict" = "true" ]; then
				vaultname_conflict_message="\nThe crypto vault label you have chosen ($CRYPTOVAULT_LABEL) conflicts with an already mapped vault.\n\nPlease choose another label/filename!"
			else
				vaultname_conflict_message="\nThe crypto vault label you have chosen ($CRYPTOVAULT_LABEL) conflicts with an existing vault file at your chosen vault file path ($VAULTFILE_HOME).\n\nPlease choose another label/filename!"
			fi

			dialog --title "ERROR" --msgbox "$vaultname_conflict_message" 14 50
			VAULTFILE_FQFN=""

		else
			dialog --title "Confirm selected label/filename" --yesno "\nYou selected crypto vault label / file name:\n\n${CRYPTOVAULT_LABEL}\n\nThe full vault file path will be:\n\n${VAULTFILE_FQFN}\n\nIs this what you want?" 16 70
			_ret=$?

			case ${_ret} in
				0)
					break
					;;
				1)
					;;
			esac
		fi
	fi
done

# VAULT MOUNTPOINT
# $initial_suggested_mountpoint_dir comes from preincrement (double-checking here..)
get_first_available_dir suggested_mountpoint_dir $initial_suggested_mountpoint_dir "any_empty"

if [ "$current_user" = "root" ]; then
	mountpoint_example="\nSuggested system-wide mountpoint location: ${suggested_mountpoint_dir}"
else
	mountpoint_example="\nSuggested mountpoint location: ${suggested_mountpoint_dir}"
fi

while true; do
	dialog --title "Mountpoint selection" --msgbox "\nOn the next screen select the location where you want the vault to be mounted when opened. 
If this is a system-wide vault, use a path under /mnt/. For a personal vault, select a mountpoint directory under a home directory.\n\n
NOTE: Use Up/Dn [arrow] to move to move the selector, SPACE to copy selected directory to the edit line, and ENTER to accept the current path in the edit box. To move to subdir/parent, add/remove \"/\" after the directory name on the edit line.\n\n
NOTE: If a non-existent path is entered, the directory/directories will be created. Existing but non-empty directories are not accepted. This directory can not be used for other purposes.\n\n
NOTE: Global locations (e.g. /mnt/cryptovault) are set up for root access, while user-owned locations (e.g. /home/alice/cryptovault) are set up for the owner of the parent dir (i.e. \"alice\" in this example).\n\n
NOTE: To accept the suggested mountpoint, just hit Enter on the next screen.\n\n
${mountpoint_example}" 28 85

	MOUNTPOINT=$(dialog --title "Mountpoint selection" --dselect ${suggested_mountpoint_dir} 16 60 2>&1 > /dev/tty)
	_ret=$?

	# remove slash from the end if there is one
	MOUNTPOINT=${MOUNTPOINT%/}

	case ${_ret} in
		0)
			;;
		1)
			early_exit && continue
			;;
	esac

	find_existing_parent mountpath_existing_parent $MOUNTPOINT
	find_dir_owner mountpath_owner ${mountpath_existing_parent}
	# get this result array via a global set by find_existing_parent, called above
	mountpath_first_created=${fep_result[2]}

	different_owners_WARNING=""
	if [ "$vaultpath_owner" != "$mountpath_owner" ]; then
		different_owners_WARNING="WARNING: THE VAULT FILE PATH ($VAULTFILE_HOME), AND THE MOUNTPOINT PATH ($MOUNTPOINT) ARE OWNED BY DIFFERENT USERS (\"$vaultpath_owner\" and \"$mountpath_owner\", respectively). I can proceed, but this is *probably* not what you want!\n\n"
	fi

	# since the target mountpoint location is different from the current user, 
	# if this is not executed as root, sudo is required for the related filesystem operations
	if [ "$current_user" != "$mountpath_owner" ] &&
		[ "$im_root" = "false" ]; then

		mount_fileop_sudoreq="true"
	else
		mount_fileop_sudoreq="false"
	fi

	# check if the tentative mountpoint is an ancestor to the previously selected vault file home directory
	dir_is_ancestor ancestor_check "$MOUNTPOINT" "$VAULTFILE_HOME"

	mountpoint_info=""
	confirm="false"
	mountpoint_exists="true"
	if [ "$MOUNTPOINT" = "$VAULTFILE_HOME" ]; then
		mountpoint_selection_info="Vault file path and the mountpoint cannot be the same directory; the mountpoint directory must always remain empty."

	elif [ "$ancestor_check" = "true" ]; then
		mountpoint_selection_info="The mountpoint directory you have selected is an ancestor to the the vault file path you selected earlier. Since the mountpoint directory must always remain empty, you must choose a different location."

	else    
		if [ -d "$MOUNTPOINT" ]; then
			if [ "$(ls -A $MOUNTPOINT)" ]; then
				mountpoint_selection_info="This directory is not empty.\n\nSelect an empty directory, or create new."
			else
				mountpoint_selection_info="This directory exists and it is empty."
				confirm="true"
			fi
		else
			mountpoint_owner_info=""
			if [ "$current_user" != "$mountpath_owner" ]; then
				if [ "$mountpath_owner" = "root" ]; then
					mountpoint_owner_info="The selected mountpoint path is a system location, and will be owned by the root user.\n\n"
				else
					mountpoint_owner_info="The selected location is owned by user \"$mountpath_owner\", and the mountpoint will be made private to that user.\n\n"
				fi
			fi

			mountpoint_selection_info="This directory does not exist; it will be created."
			confirm="true"
			mountpoint_exists="false"
		fi
	fi

	if [ "$confirm" = "true" ]; then
		dialog --title "Confirm selected mountpoint" --yesno "\n${different_owners_WARNING}You selected mountpoint path:\n\n${MOUNTPOINT}\n\n${mountpoint_selection_info}\n\n${mountpoint_owner_info}Is this what you want?" 15 75
		_ret=$?

		case ${_ret} in
			0)
				break
				;;
			1)
				;;
		esac

	else
		dialog --title "ERROR" --msgbox "\n${mountpoint_selection_info}" 15 70
	fi
done

vaultpath_owner_home=$(getent passwd ${vaultpath_owner} | cut -d: -f6)

# CRYPTO VAULT COMMAND DIRECTORY (require an empty, or previuosly non-existing directory)
if [ "$vaultpath_owner" = "root" ]; then
	initial_suggested_command_dir="/usr/local/bin/${CRYPTOVAULT_LABEL}-commands"
	get_first_available_dir suggested_command_dir $initial_suggested_command_dir "any_empty"
	commanddir_example="Suggested system-wide command directory: ${suggested_command_dir} (or use \"/root/${suggested_command_dir}\" if this is a vault for the root user)"
else
	initial_suggested_command_dir="${vaultpath_owner_home}/bin/${CRYPTOVAULT_LABEL}-commands"
	get_first_available_dir suggested_command_dir $initial_suggested_command_dir "any_empty"
	commanddir_example="Suggested command directory (the home directory of the crypto vault owner is based on the vault file location): ${suggested_command_dir}"
fi

while true; do
	dialog --title "Command directory selection" --msgbox "\nOn the next screen select the directory where you want the crypto vault command scripts to be reside.\n\n
If this is a system-wide vault, select a location under \"/opt\" or \"/usr/local/bin\". For a personal vault, a location under the vault file owner's home directory (\"${vaultpath_owner_home}\") is recommended.\n\n
NOTE: When a user directory is selected, the vault mount/unmount commands are made executable by the user who owns the selected parent. When a system location (or /root) is selected, the vault mount/unmount commands are made executable only by the root user, and hence the non-privileged users must use sudo to execute them. The generated commands can be moved to a different location (they use absolute paths).\n\n
NOTE: Use Up/Dn [arrow] to move to move the selector, SPACE to copy selected directory to the edit line, and ENTER to accept the current path in the edit box. To move to subdir/parent, add/remove \"/\" after the directory name on the edit line.\n\n
${commanddir_example}" 26 90

	CRYPTOVAULT_COMMANDDIR=$(dialog --title "Command directory selection" --dselect ${suggested_command_dir} 16 60 2>&1 > /dev/tty)
	_ret=$?

	# remove slash from the end if there is one
	CRYPTOVAULT_COMMANDDIR=${CRYPTOVAULT_COMMANDDIR%/}

	case ${_ret} in
		0)
			;;
		1)
			early_exit && continue
			;;
	esac

	find_existing_parent commanddir_existing_parent $CRYPTOVAULT_COMMANDDIR
	find_dir_owner commanddir_parent_owner ${commanddir_existing_parent}
	# get this result array via a global set by find_existing_parent, called above
	commanddir_first_created=${fep_result[2]}

	different_owners_WARNING=""
	if [ "$commanddir_parent_owner" != "$vaultpath_owner" ]; then
		different_owners_WARNING="WARNING: THE CRYPTO VAULT COMMAND DIRECTORY (${CRYPTOVAULT_LABEL}-commands), AND THE VAULT FILE PATH ($VAULTFILE_HOME) ARE OWNED BY DIFFERENT USERS (\"$commanddir_parent_owner\" and \"$vaultpath_owner\", respectively). If you proceed, the crypto vault owner may not be able to mount/unmount the vault!\n\n"
	elif [ "$commanddir_parent_owner" != "$mountpath_owner" ]; then
		different_owners_WARNING="WARNING: THE CRYPTO VAULT COMMAND DIRECTORY (${CRYPTOVAULT_LABEL}-commands), AND THE MOUNTPOINT PATH ($MOUNTPOINT) ARE OWNED BY DIFFERENT USERS (\"$commanddir_parent_owner\" and \"$mountpath_owner\", respectively). If you proceed, the crypto vault owner may not be able to mount/unmount the vault!\n\n"
	fi

	# since the target command dirctory location is different from the current user, 
	# if this is not executed as root, sudo is required for the related filesystem operations
	if [ "$current_user" != "$commanddir_parent_owner" ] &&
		[ "$im_root" = "false" ]; then

		command_fileop_sudoreq="true"
	else
		command_fileop_sudoreq="false"
	fi

	path_creation_info=""
	commanddir_exists="true"

	if [ ! -d "$CRYPTOVAULT_COMMANDDIR" ]; then
		path_creation_info="This directory does not exist; it will be created."
		commanddir_exists="false"
	fi

	if [ "$CRYPTOVAULT_COMMANDDIR" = "$MOUNTPOINT" ]; then
		dialog --title "ERROR" --msgbox "\nThe command directory may not be the same as the mountpoint directory you selected earlier! The mountpoint directory must always remain empty. Please select another directory for the vault command scripts." 14 50
		continue
	else      
		commanddir_owner_info=""
		if [ "$current_user" != "$commanddir_parent_owner" ]; then
			if [ "$commanddir_parent_owner" = "root" ]; then
				commanddir_owner_info="The selected command directory location is a system location, and will be owned by the root user. The crypto vault management commands will require sudo to execute by the unprivileged users.\n\n"
			else
				commanddir_owner_info="The selected location is owned by user \"$commanddir_parent_owner\", and the crypto vault management commands will be made private to that user.\n\n"
			fi
		fi

		dialog --title "Confirm the selected command directory location" --yesno "\n${different_owners_WARNING}The full path of the vault command directory:\n\n${CRYPTOVAULT_COMMANDDIR}\n\n${commanddir_owner_info}Is this what you want?" 14 75
		_ret=$?

		case ${_ret} in
			0)
				break
				;;
			1)
				;;
		esac
	fi
done

#TODO: Offer to symlink command scripts onto PATH (confirm that the path exists as expected)

dialog --title "Confirm to start crypto vault creation" --yesno "\nIf you proceed, the encrypted vault will be created with the following parameters you have entered:\n\n
Vault filesystem...........: ${CRYPTOVAULT_FS}\n
Vault size.................: ${VAULTSIZEVAL}${VAULTSIZEUNIT}\n
Vault label................: ${CRYPTOVAULT_LABEL}\n
Vault file path............: ${VAULTFILE_FQFN} (owned by ${vaultpath_owner})\n
Vault mountpoint path......: ${MOUNTPOINT} (owned by ${mountpath_owner})\n
Vault command script path..: ${CRYPTOVAULT_COMMANDDIR} (owned by ${commanddir_parent_owner})\n\n
If the values are not correct, select \"NO\", and run the script again.\n\nDo you want to proceed?" 19 110
_ret=$?
  
case ${_ret} in
	0)
		;;
	1)
		clear && echo -e "\n${BWhite}${On_Red} CRYPTO VAULT CREATION WAS CANCELLED ${Color_Off}\n\n" && exit 1
		;;
esac

# MAIN LOGIC: CREATE PATHS AND THE DISK ======================================

clear 

# enable for creation process debug
if [ "${debug_me}" = "true" ]; then
	set -x
fi

echo

trap - INT TERM
trap 'cleanup interrupt' INT TERM

executing="${BGreen}EXECUTING${Color_Off}"
if [ "$im_root" = "false" ]; then
	elevated=" ${Black}${On_Green}ELEVATED${Color_Off}"
else
	elevated=''
fi

# create vault path
vaultpath_creation_error="false"
if [ "$vaultpath_exists" = "false" ]; then
	echo -e "${BIWhite}Creating vault path...${Color_Off}"
	executable="mkdir -p $VAULTFILE_HOME"
	if [ "$vaultpath_owner" = "$current_user" ]; then
		echo -e "$executing: $executable"
		eval $executable 2>/dev/null
		_ret=$?
	else
		echo -e "${executing}$elevated (as $vaultpath_owner): $executable"
		sudoitas _ret $vaultpath_owner $executable
	fi
	if [ ${_ret} -ne 0 ]; then
		vaultpath_creation_error="true"
	fi

	# test vaultpath creation
	if [ "$vaultpath_creation_error" = "true" ] ||
		[ ! -d "$VAULTFILE_HOME" ]; then

		echo -e "${BWhite}${On_Red}Could not create vault path \"${VAULTFILE_HOME}\". Unable to proceed.${Color_Off}"
		cleanup
	fi
fi

echo

# create blank vault container file
vaultfile_creation_error="false"
echo -e "${BIWhite}Creating blank vault container file...${Color_Off}"
if [ "$VAULTSIZEUNIT" = "GB" ]; then
	let vaultsize=$VAULTSIZEVAL*1024
else
	vaultsize=$VAULTSIZEVAL
fi

executable="dd if=/dev/zero of=${VAULTFILE_FQFN} bs=1M count=$vaultsize"
if [ "$vaultpath_owner" = "$current_user" ]; then
	echo -e "$executing: $executable"
	eval $executable 2>/dev/null
	if [ $? -ne 0 ]; then
		vaultfile_creation_error="true"
	fi

else

	echo -e "${executing}$elevated (as $vaultpath_owner): $executable"
	sudoitas _ret $vaultpath_owner $executable
	if [ ${_ret} -ne 0 ]; then
		vaultfile_creation_error="true"
	fi
fi

# test blank vaultfile creation
if [ "$vaultfile_creation_error" = "true" ] ||
	[ ! -e "${VAULTFILE_FQFN}" ]; then

	echo -e "${BWhite}${On_Red}Could not create vault container file \"${VAULTFILE_FQFN}\". Unable to proceed.${Color_Off}"
	cleanup
fi

echo

# create mountpoint path
mountpoint_creation_error="false"
if [ "$mountpoint_exists" = "false" ]; then
	echo -e "${BIWhite}Creating the mountpoint (an empty directory)...${Color_Off}"
	
	executable="mkdir -p $MOUNTPOINT"
	if [ "$mountpath_owner" = "$current_user" ]; then
		echo -e "$executing: $executable"
		eval $executable 2>/dev/null
		if [ $? -ne 0 ]; then
			mountpoint_creation_error="true"
		fi
	else
		echo -e "${executing}$elevated (as $mountpath_owner): $executable"
		sudoitas _ret $mountpath_owner $executable
		if [ ${_ret} -ne 0 ]; then
			mountpoint_creation_error="true"
		fi
	fi
  
	# test to make sure mountpath got created
	if [ "$mountpoint_creation_error" = "true" ] ||
		[ ! -d "$MOUNTPOINT" ]; then

		echo -e "${BWhite}${On_Red}Could not create the mountpoint at \"${MOUNTPOINT}\". Unable to proceed.${Color_Off}"
		cleanup
	fi
fi

echo

# format the container
echo -e "${BIWhite}Formatting the container with encrypted LUKS filesystem...${Color_Off}"
echo -e "${executing}$elevated: cryptsetup luksFormat -q ${VAULTFILE_FQFN}"

if [ "$im_root" = "false" ]; then
	if ! sudo -n true 2>/dev/null; then 
		echo -e "${IYellow}This operation may require you to re-enter your sudo password below:${Color_Off}"
	fi
	echo -n "$CRYPTPWD" | sudo cryptsetup luksFormat -q ${VAULTFILE_FQFN} -
	_ret=${PIPESTATUS[1]}
else
	# running as root, no sudo needed (even when creting for a different user, this is only access to cryptsetup command)
	echo -n "$CRYPTPWD" | cryptsetup luksFormat -q ${VAULTFILE_FQFN} -
	_ret=${PIPESTATUS[1]}
fi

# test to make sure container gets formatted
if [ ${_ret} -ne 0 ]; then
	echo -e "${BWhite}${On_Red}Could not format the vault container with LUKS at \"${VAULTFILE_FQFN}\". Unable to proceed.${Color_Off}"
	cleanup
fi

echo

# set up the loop device
echo -e "${BIWhite}Setting up the loop device...${Color_Off}"
if ! sudo -n true 2>/dev/null; then 
	echo -e "${IYellow}This operation may require you to re-enter your sudo password below:${Color_Off}"
fi
loopdev=$(sudo losetup -f)
echo "Using loop device: $loopdev"
executable="losetup $loopdev ${VAULTFILE_FQFN}"
echo -e "${executing}$elevated: $executable"
sudoit _ret $executable

# make sure the loop device got set up
loopdev_by_label=$(sudo losetup --raw | grep ${CRYPTOVAULT_LABEL} | awk '{print $1}')
if [ ${_ret} -ne 0 ] ||
	[ "$loopdev_by_label" != "$loopdev" ]; then

	echo -e "${BWhite}${On_Red}Could not set up the loop device. Unable to proceed.${Color_Off}"
	cleanup
fi

echo

# open the mapped loop device (req. selected encryption password)
echo -e "${BIWhite}Opening the mapped device...${Color_Off}"
executable="cryptsetup luksOpen $loopdev ${CRYPTOVAULT_LABEL}"
echo -e "${executing}$elevated: $executable"
echo -e "${IYellow}The encrypted device is being opened. Please enter below the encryption password\nyou selected earlier in the process (NOTE: typed characters will not echo).${Color_Off}"
sudoit _ret $executable

if [ ${_ret} -ne 0 ]; then
	echo -e "${BWhite}${On_Red}Could not open the loop device (are you sure you entered the decryption password correctly?). Unable to proceed.${Color_Off}"
	cleanup
fi

echo

# create and mount the filesystem
echo -e "${BIWhite}Creating the ${CRYPTOVAULT_FS} filesystem...${Color_Off}"
if [ "$CRYPTOVAULT_FS" = "zfs" ]; then
	zpool_id="zpool-${CRYPTOVAULT_LABEL}"
	echo "zpool ID for this crypto vault is: $zpool_id"
	executable="zpool create -o ashift=12 -O atime=off -O compression=lz4 -O normalization=formD -O mountpoint=/ -m ${MOUNTPOINT} $zpool_id /dev/mapper/${CRYPTOVAULT_LABEL}"
	echo -e "${executing}$elevated: $executable"  
	sudoit _ret $executable
	echo "Currently mounted zfs filesystems:"
	sudoit _ret zfs list
else
	executable="mkfs.ext4 /dev/mapper/${CRYPTOVAULT_LABEL}"
 	echo -e "${executing}$elevated: $executable"
	sudoit _ret $executable
	executable_mount="mount /dev/mapper/${CRYPTOVAULT_LABEL} ${MOUNTPOINT}"
	echo "Mounting ext4 filesystem..."
	echo -e "${executing}$elevated: $executable_mount"
	sudoit _ret $executable_mount
fi

# test the mount
check_mounted mount_in_proc $MOUNTPOINT
if [ "$mount_in_proc" = "false" ] ||
	[ ${_ret} -ne 0 ]; then

	echo -e "${BWhite}${On_Red}Could not mount the crypto vault at  \"${MOUNTPOINT}\". Unable to proceed.${Color_Off}"
	cleanup
fi

if [ "$mountpath_owner" != "root" ]; then
	echo
	echo -e "${BIWhite}Setting the mountpoint permissions...${Color_Off}"
	executable="chmod 770 ${MOUNTPOINT}"
	echo -e "${executing}$elevated: $executable"
	sudoit _ret $executable
	executable="chown -R ${mountpath_owner} ${MOUNTPOINT}"
	echo -e "${executing}$elevated: $executable"
	sudoit _ret $executable
fi

echo 


# MAIN LOGIC: CREATE THE UTILITY SCRIPTS =====================================

if [ ! -d ${SCRIPT_DIR}/_stubs ] ||
	[ ! -f ${SCRIPT_DIR}/_stubs/mount-crypto ] ||
	[ ! -f ${SCRIPT_DIR}/_stubs/umount-crypto ] ||
	[ ! -f ${SCRIPT_DIR}/_stubs/util-crypto ]; then

	echo "The utility script stubs in \"_stubs\" subdirectory are missing. Unable to proceed. Please make sure that you have not altered the cloned \"cryptovault\" repository (https://github.com/vwal/cryptovault), and try again!"
	cleanup 
fi

#TODO: Can the command script directory be named without the suggested user name? 
# create command script directory
commanddir_creation_error="false"
if [ "$commanddir_exists" = "false" ]; then
	echo -e "${BIWhite}Creating command script directory...${Color_Off}"
	executable="mkdir -p ${CRYPTOVAULT_COMMANDDIR}"
	if [ "$command_fileop_sudoreq" = "false" ]; then
		echo -e "$executing: $executable"
		eval $executable 2>/dev/null
		_ret=$?
	else
		echo -e "${executing}$elevated (as $commanddir_parent_owner): $executable"
		sudoitas _ret $commanddir_parent_owner $executable
	fi
	if [ ${_ret} -ne 0 ]; then
		commanddir_creation_error="true"
	fi

	# test commanddir creation
	if [ "$commanddir_creation_error" = "true" ] ||
		[ ! -d "$CRYPTOVAULT_COMMANDDIR" ]; then

		echo -e "${BWhite}${On_Red}Could not create command script directory \"${CRYPTOVAULT_COMMANDDIR}\". Unable to proceed.${Color_Off}"
		cleanup
	fi
fi

# centralized error check for the command script customization functions
tempfile_customization_validation() {
	local retval="$1"
	local step="$2"

	if [ "$retval" != "0" ]; then
		echo "Error in customizing the vault command scripts (failed while ${step}). Unable to proceed."
	fi
}

# create file descriptor reference to a deleted temp file (automatically purged on exit)
tmpfile=$(mktemp /tmp/tmp.1234567890XXXXXX)
tempfile_customization_validation $? "creting tempfile"

exec 3>"$tmpfile"
tempfile_customization_validation $? "creating tempfile handle"

rm "$tmpfile"
tempfile_customization_validation $? "removing tempfile ${tmpfile}"

echo -e "\n${BIWhite}Adding the vault-specific configuration variables to the command script stubs...${Color_Off}"

# NOTE: The non-standard code indentation on the following items is intentional; do not modify it!


# MOUNT SCRIPT...

# prepare mount script
if [ "$CRYPTOVAULT_FS" = "zfs" ]; then
	echo -e "#!/bin/bash\n
CRYPTOVAULT_FS=${CRYPTOVAULT_FS}
CRYPTOVAULT_FQFN=${VAULTFILE_FQFN}
CRYPTOVAULT_MOUNTPOINT=${MOUNTPOINT}
CRYPTOVAULT_LABEL=${CRYPTOVAULT_LABEL}
ZPOOL_ID=${zpool_id}\n" > /dev/fd/3

	tempfile_customization_validation $? "preparing zfs mount script variables"

else

	echo -e "#!/bin/bash\n
CRYPTOVAULT_FS=${CRYPTOVAULT_FS}
CRYPTOVAULT_FQFN=${VAULTFILE_FQFN}
CRYPTOVAULT_MOUNTPOINT=${MOUNTPOINT}
CRYPTOVAULT_LABEL=${CRYPTOVAULT_LABEL}\n" > /dev/fd/3

	tempfile_customization_validation $? "preparing ext4 mount script variables"

fi

#TODO: add "EXECUTING" outputs to the process

# append stub file into the temp file descriptor
if [ "$command_fileop_sudoreq" = "false" ]; then
	cat "${SCRIPT_DIR}/_stubs/mount-crypto" >> /dev/fd/3
	_ret=$?
else
	sudoit _ret cat "${CRYPTOVAULT_COMMANDDIR}/mount-${CRYPTOVAULT_LABEL}" >> /dev/fd/3
fi
tempfile_customization_validation ${_ret} "appending mount script stub"

# write the customized script into the vault command directory
if [ "$command_fileop_sudoreq" = "false" ]; then
	cat /dev/fd/3 | dd of="${CRYPTOVAULT_COMMANDDIR}/mount-${CRYPTOVAULT_LABEL}" &> /dev/null
	_ret=$?
else
	cat /dev/fd/3 | sudoit _ret dd of="${CRYPTOVAULT_COMMANDDIR}/mount-${CRYPTOVAULT_LABEL}" &> /dev/null
fi

tempfile_customization_validation ${PIPESTATUS[0]} "outputting customized mount script from the temp file handle"
tempfile_customization_validation ${_ret} "writing output from the temp file handle into mount script file"

# purge the file descriptor
cat /dev/null > /dev/fd/3
tempfile_customization_validation $? "purging the temporary file handle after mount script creation"

echo "Crypto vault mount script now ready at ${CRYPTOVAULT_COMMANDDIR}/mount-${CRYPTOVAULT_LABEL}"


# UMOUNT SCRIPT...

# prepare umount script
echo -e "#!/bin/bash\n
CRYPTO_FQFN=${VAULTFILE_FQFN}
CRYPTO_MOUNTPOINT=${MOUNTPOINT}
CRYPTO_LABEL=${CRYPTOVAULT_LABEL}
ZPOOL_ID=${zpool_id}\n" > /dev/fd/3

tempfile_customization_validation $? "preparing umount script variables"

# append stub file into the temp file descriptor
if [ "$command_fileop_sudoreq" = "false" ]; then
	cat "${SCRIPT_DIR}/_stubs/umount-crypto" >> /dev/fd/3
	_ret=$?
else
	sudoit _ret cat "${CRYPTOVAULT_COMMANDDIR}/umount-${CRYPTOVAULT_LABEL}" >> /dev/fd/3
fi
tempfile_customization_validation ${_ret} "appending umount script stub"

# write the customized script into the vault command directory
if [ "$command_fileop_sudoreq" = "false" ]; then
	cat /dev/fd/3 | dd of="${CRYPTOVAULT_COMMANDDIR}/umount-${CRYPTOVAULT_LABEL}" &> /dev/null
	_ret=$?
else
	cat /dev/fd/3 | sudoit _ret dd of="${CRYPTOVAULT_COMMANDDIR}/umount-${CRYPTOVAULT_LABEL}" &> /dev/null
fi

tempfile_customization_validation ${PIPESTATUS[0]} "outputting customized umount script from the temp file handle"
tempfile_customization_validation ${_ret} "writing output from the temp file handle into umount script file"

# purge the file descriptor
cat /dev/null > /dev/fd/3
tempfile_customization_validation $? "purging the temporary file handle after umount script creation"

echo "Crypto vault umount script now ready at ${CRYPTOVAULT_COMMANDDIR}/umount-${CRYPTOVAULT_LABEL}"


# UTIL SCRIPT...

# prepare the util script
echo -e "#!/bin/bash\n
CRYPTOVAULT_FS=${CRYPTOVAULT_FS}
CRYPTO_FQFN=${VAULTFILE_FQFN}
CRYPTO_MOUNTPOINT=${MOUNTPOINT}
CRYPTO_LABEL=${CRYPTOVAULT_LABEL}
ZPOOL_ID=${zpool_id}\n" > /dev/fd/3

tempfile_customization_validation $? "preparing util script variables"

# append stub file into the temp file descriptor
if [ "$command_fileop_sudoreq" = "false" ]; then
	cat "${SCRIPT_DIR}/_stubs/util-crypto" >> /dev/fd/3
	_ret=$?
else
	sudoit _ret cat "${CRYPTOVAULT_COMMANDDIR}/util-${CRYPTOVAULT_LABEL}" >> /dev/fd/3
fi
tempfile_customization_validation ${_ret} "appending util script stub"

# write the customized script into the vault command directory
if [ "$command_fileop_sudoreq" = "false" ]; then
	cat /dev/fd/3 | dd of="${CRYPTOVAULT_COMMANDDIR}/util-${CRYPTOVAULT_LABEL}" &> /dev/null
	_ret=$?
else
	cat /dev/fd/3 | sudoit _ret dd of="${CRYPTOVAULT_COMMANDDIR}/util-${CRYPTOVAULT_LABEL}" &> /dev/null
fi

tempfile_customization_validation ${PIPESTATUS[0]} "outputting customized util script from the temp file handle"
tempfile_customization_validation ${_ret} "writing output from the temp file handle into util script file"

# purge the file descriptor
cat /dev/null > /dev/fd/3
tempfile_customization_validation $? "purging the temporary file handle after util script creation"

echo "Crypto vault utility script now ready at ${CRYPTOVAULT_COMMANDDIR}/util-${CRYPTOVAULT_LABEL}"
echo

# set the owner for the command directory/scripts
echo -e "${BIWhite}Setting the owner for the vault command scripts...${Color_Off}"
executable="chown -R ${commanddir_parent_owner}:${commanddir_parent_owner} ${CRYPTOVAULT_COMMANDDIR}"
echo -e "${executing}$elevated: $executable"
sudoit _ret $executable

if [ ${_ret} -eq 0 ]; then
	echo "Vault command directory/script owner set."
else
	echo "Unable to set the correct owner for the vault command directory/scripts. Unable to proceed."
	cleanup
fi

# set the permsissions for the command directory/scripts
echo -e "${BIWhite}Setting the permissions for the vault command scripts...${Color_Off}"
executable="chmod -R 750 ${CRYPTOVAULT_COMMANDDIR}"
echo -e "${executing}$elevated: $executable"
sudoit _ret $executable

if [ ${_ret} -eq 0 ]; then
	echo "Vault command directory/script permissions set."
else
	echo "Unable to set the necessary permissions for the vault command directory/scripts. Unable to proceed."
	cleanup
fi

# MAIN LOGIC: PROCESS COMPLETED; WRAPPING UP =================================

# confirm to keep the vault (the final option to fully bail out)
echo
echo -n "Crypto vault \"${CRYPTOVAULT_LABEL}\" has been created. Keep this new vault (y/n)? "
yesno _ret
if [ "$_ret" = "no" ]; then
	echo
	echo "Destroying the created crypt disk."
	cleanup
else

	# deactivate 'cleanup interrupt' trap (INT TERM)
	trap - INT TERM

	# activate 'cleanup nodelete' trap (INT TERM)
	trap 'echo && echo "Closing the crypto vault." && cleanup nodelete' INT TERM

	dialog --title "Lock/unmount the new crypto vault?" --yesno "\nDo you want to leave the newly created crypto vault mounted and unlocked at \"${MOUNTPOINT}\"?\n\n
You can unmount/lock and remount/unlock the crypto vault at any time using the \"mount-${CRYPTOVAULT_LABEL}\" and \"umount-${CRYPTOVAULT_LABEL}\" scripts which have been created at \"${CRYPTOVAULT_COMMANDDIR}\"." 20 70
	_ret=$?

	case ${_ret} in
		0)
			clear && echo && echo "Leaving the crypto vault open at ${MOUNTPOINT}" && exit_info
			;;
		1)
			clear && echo && echo "Closing the crypto vault." && cleanup nodelete
			;;
	esac

#TODO: add a final note about the management commands (their location, use and who can use them natively/with sudo)

fi
