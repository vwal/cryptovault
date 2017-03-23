#!/bin/bash

trap early_exit INT TERM

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
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# purge sudo password cache (if set previously), and reset other sudo related variables
sudo -k
SUDOPWD=
# check if the user is allowed to execute sudo without a password
if sudo -n true 2>/dev/null; then
  is_sudo=1
else
  is_sudo=0
fi

# assume either root execution, or creating vault for oneself
vault_fileop_sudoreq="false"
mount_fileop_sudoreq="false"

# who *am* I?
login_user=$(logname)
current_user=$(whoami)
# am I root??
if [ "$EUID" -eq 0 ]; then
  im_root="true"
else
  im_root="false"
fi

CRYPTPWD=

# Define the dialog exit status codes
: ${DIALOG_OK=0}
: ${DIALOG_CANCEL=1}


# FUNCTIONS ==================================================================

# exists for commands
exists() {
  command -v "$1" >/dev/null 2>&1
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
    ret=$?

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
    case $ret in
      0)
        validate_sudopwd;;
      1)
        exit 1;;
    esac
  done
}

# sudo for system operations
# use the locally cached sudo password if sudo doesn't cache the password by policy (or if it has expired)
sudoit() {
  # $1 is the retval (_ret)

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

  eval "$1=$_ret"  
}

# always sudo because executing as a different user
# use the locally cached sudo password if sudo doesn't cache the password by policy (or if it has expired)
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

  eval "$1=$_ret"
}

# find the first existing parent of the given dir
find_existing_parent() {
  pathname="$2"

  if [ -d "$pathname" ]; then
    eval "$1=$2"  
  else
    IFS='/' read -r -a p <<<"${pathname#/}"

    pa=""
    max="${#p[@]}"
    i=0
    while (( i<"$max" )); do
      paprev=$pa
      pa="$pa/${p[i++]}"
      if [[ ! -e $pa ]]; then
        eval "$1=$paprev"
        break
      fi
    done
  fi
}

# who owns the given dir
find_dir_owner() {
  dirowner=$(ls -ld $2 | awk '{print $3}')
  eval "$1=$dirowner"
}

# check mountpath against mounts in /proc/mounts
check_mounted() {
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
  echo -e "\e${BIRed}Cleaning up...\e${Color_Off}"  

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
            echo -e "\e${IYellow}This operation may require you to re-enter your sudo password below:\e${Color_Off}"
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
            echo -e "\e${IYellow}This operation may require you to re-enter your sudo password below:\e${Color_Off}"
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
    echo -e "\e${IYellow}This operation may require you to re-enter your sudo password below:\e${Color_Off}"
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
    exit_info
    
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
    fi

    # remove the vault directory
    if [ -d $VAULTFILE_HOME ] &&
       [ "$vaultpath_exists" = "false" ] &&
       [ ! "$(ls -A $VAULTFILE_HOME)" ]; then
     
      if [ "$vault_fileop_sudoreq" = "false" ]; then
        rmdir "$VAULTFILE_HOME"
        _ret=$?
      else
        sudoit _ret rmdir "$VAULTFILE_HOME"      
      fi

      if [ ${_ret} -ne 0 ]; then
        echo "Unable to remove the vault directory \"$VAULTFILE_HOME\"."
      else
        echo "Vault directory \"$VAULTFILE_HOME\" removed (it was created during this process, and was now empty)."
      fi
     
    else
      echo "Vault directory was not created by this process. Leaving it intact."
    fi

    if [ -d $MOUNTPOINT ] &&
       [ "$mountpoint_exists" = "false" ] &&
       [ ! "$(ls -A $MOUNTPOINT)" ]; then
      
      if [ "$vault_fileop_sudoreq" = "false" ]; then
        rmdir "$MOUNTPOINT"
        _ret=$?
      else
        sudoit _ret rmdir "$MOUNTPOINT"      
      fi

      if [ ${_ret} -ne 0 ]; then
        echo "Unable to remove the mountpoint directory \"$MOUNTPOINT\"."
      else
        echo "Mountpoint directory \"$MOUNTPOINT\" removed (it was created during this process, and was empty)."
      fi      

    else
      echo "Mountpoint directory was not created by this process. Leaving it intact."
    fi

    if [ -d $CRYPTOVAULT_COMMANDDIR ]; then

      #TODO: is sudo required? Even for the test above?
      # use, probably, mount_fileop_sudoreq (although there may be further detail for this: mount_owner's home, SCRIPTHOME...)

      rm -rf $CRYPTOVAULT_COMMANDDIR
      echo "Generated command files removed."
    fi

    echo
    echo "Cleanup complete. Exiting."
    echo

    exit 1

  fi
  
}

# exit before the action begins
early_exit() {
  clear
  echo
  echo "Crypto disk creation cancelled."
  echo
  
  exit 1
}

# clean exit
exit_info() {
  echo
  echo "Please use the \"mount-${CRYPTOVAULT_LABEL}\" and \"umount-${CRYPTOVAULT_LABEL}\" command files at ${CRYPTOVAULT_COMMANDDIR} to mount and dismount your newly created crypto vault \"${CRYPTOVAULT_LABEL}\"."
  echo
  
  exit 0
}



# PREREQS CHECKS =============================================================

if ! exists dialog ; then
  printf "\n*************************************************************************************************\n\
This script requires dialog. Install it first with 'sudo apt-get install dialog', then try again!\n\
*************************************************************************************************\n\n"
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
  printf "\n*********************************************************************************************************\n\
This script requires cryptsetup. Install it first with 'sudo apt-get install cryptsetup', then try again!\n\
*********************************************************************************************************\n\n"
  exit 1
fi


# MAIN LOGIC: QUERY VAULT PARAMETERS =========================================

# FILE SYSTEM SELECTION
SELECT_CRYPTO_FS=$(dialog --title "Select crypto vault file system" --radiolist "\nSelect the file system for the encrypted vault.\nZFS is recommended for multiple reasons.\n\n
NOTE: Highlight the choice with up/down arrow, select with SPACE." 20 55 2 \
            1 zfs on \
            2 ext4 off \
          2>&1 > /dev/tty)
ret=$?

# ok (proceed) / cancel
case $ret in
  0)
    ;;
  1)
    exit 1;;
esac

if [ "$SELECT_CRYPTO_FS" = "1" ]; then
  CRYPTOVAULT_FS="zfs"

  ZFS=$(sudo which zfs)
  if [ $? -ne 0 ]; then
    printf "\n\n**************************************************************************************************************************************\n\
To use ZFS filesystem zfsutils-linux package is required. Install it first with 'sudo apt-get install zfsutils-linux', then try again!\
\n**************************************************************************************************************************************\n\n\n"
    exit 1
  fi

else
  CRYPTOVAULT_FS="ext4"
fi


# ENCRYPTION PASSWORD SELECTION
while true; do
  CRYPT_PASS_SEL_1=$(dialog --title "Enter encryption password" --insecure --passwordbox "\nEnter the passphrase you want the vault to be encrypted with.\n\n" 12 50  2>&1 > /dev/tty)
  ret=$?

  # ok (proceed) / cancel
  case $ret in
    0)
      ;;
    1)
      exit 1;;
  esac

  CRYPT_PASS_SEL_2=$(dialog --title "Repeat encryption password" --insecure --passwordbox "\nEnter again the passphrase you want the vault to be encrypted with.\n\n" 12 50 2>&1 > /dev/tty)
  ret=$?

  # ok (proceed) / cancel
  case $ret in
    0)
      ;;
    1)
      exit 1;;
  esac

  if [ "${CRYPT_PASS_SEL_1}" = "${CRYPT_PASS_SEL_2}" ]; then

    if [ "${CRYPT_PASS_SEL_1}" = "" ]; then
      dialog --title "ERROR" --msgbox "\nAn empty passphrase is not allowed!\n\nPlease try again!" 9 30
    else 
      CRYPTPWD=$CRYPT_PASS_SEL_1
      break
    fi
  else
    dialog --title "ERROR" --msgbox "\nPASSPHRASES DO NOT MATCH!!\n\nPlease try again!" 9 30
  fi
done


# VAULT SIZE SELECTION
while true; do
  CRYPTOVAULTSIZEINPUT=$(dialog --title "Enter desired crypto vault size" --inputbox "\nEnter the desired crypto vault size in\nmegabytes (MB) or gigabytes (GB).\n\nPlease be mindful of the available drive space.\n\n" 14 55 512MB 2>&1 > /dev/tty)
  ret=$?

  # ok (proceed) / cancel
  case $ret in
    0)
      ;;
    1)
      exit 1;;
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
if [ "$current_user" = "root" ]; then
  vaulthome_example="\nSuggested system-wide mountpoint location: /mnt/cryptovault"
else
  vaulthome_example="\nSuggested mountpoint location: ${HOME}/cryptovault"
fi

while true; do
  dialog --title "Vault file location selection" --msgbox "\nOn the next screen select the location where you want the vault file to be saved. 
If this is a system-wide vault, use a path, for example, under /var/ (such as /var/vaultfiles). For a personal vault, select a location under a home directory (e.g. /home/alice/vaultfiles).\n\n
NOTE: In this step you will select the directory where the vault file is saved. In the next step you will select the vault file name/label.\n\n
NOTE: Use Up/Dn [arrow] to move to move the selector, SPACE to copy selected directory to the edit line, and ENTER to accept the current path in the edit box. 
To move to subdir/parent, add/remove \"/\" after the directory name on the edit line.\n\n
NOTE: If a non-existent path is entered, the directory/directories will be created.\n\n
${vaulthome_example}" 25 75

  VAULTFILE_HOME=$(dialog --title "Vault file location selection" --dselect ${HOME}/ 16 60 2>&1 > /dev/tty)
  ret=$?

  #remove slash from the end if there is one
  VAULTFILE_HOME=${VAULTFILE_HOME%/}
  
  case $ret in
    0)
      ;;
    1)
      exit 1;;
  esac

  find_existing_parent vaultpath_existing_parent $VAULTFILE_HOME
  find_dir_owner vaultpath_owner $vaultpath_existing_parent

  vaulthome_owner_info=""
  if [ "$current_user" != "$vaultpath_owner" ]; then
    if [ "$vaultpath_owner" = "root" ]; then
      vaulthome_owner_info="The selected location a system location, and will be owned by the root user.\n\n"
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
  fi

  dialog --title "Confirm selected vault file location" --yesno "\nYou selected vault file location:\n\n${VAULTFILE_HOME}\n\n${path_creation_info}\n\n${vaulthome_owner_info}Is this what you want?" 16 70
  ret=$?
  
  case $ret in
    0)
      break;;
    1)
      ;;
  esac
  
done


# VAULT LABEL/FILE NAME
while true; do
  CRYPTOVAULT_LABEL_INPUT=$(dialog --title "Crypto Vault Label/File Name" --inputbox "\nEnter the desired crypto vault label (no spaces). It will also be used as the crypto vault file name.\n\n
NOTE: Since the crypto vaults are mapped through /dev/mapper system-wide (even when access is limited to a specific user), the label must be unique on the system.\n" 15 55 2>&1 > /dev/tty)
  ret=$?

  # ok (proceed) / cancel
  case $ret in
    0)
      ;;
    1)
      exit 1;;
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

    for i in $VAULTFILE_HOME/*; do
      thisbase=$(basename $i)
      if [ "$thisbase" = "$CRYPTOVAULT_LABEL" ]; then
        vaultname_conflict="true"
      fi
    done

    if [ "$vaultname_conflict" = "true" ]; then
      if [ "$mapper_conflict" = "true" ]; then
         vaultname_conflict_message="\nThe crypto vault label you have chosen ($CRYPTOVAULT_LABEL) conflicts with an already mapped vault.\n\nPlease choose another label/filename!"
      else
         vaultname_conflict_message="\nThe crypto vault label you have chosen ($CRYPTOVAULT_LABEL) conflicts with an existing vault file at your chosen vault file path ($VAULTFILE_HOME).\n\nPlease choose another label/filename!"
      fi    

      dialog --title "ERROR" --msgbox "$vaultname_conflict_message" 14 50
      ret=$?
  
      case $ret in
        0)
          ;;
        1)
          exit 1;;
      esac

    else
      VAULTFILE_FQFN=${VAULTFILE_HOME}/${CRYPTOVAULT_LABEL}
      dialog --title "Confirm selected label/filename" --yesno "\nYou selected crypto vault label / file name:\n\n${CRYPTOVAULT_LABEL}\n\nThe full vault file path will be:\n\n${VAULTFILE_FQFN}\n\nIs this what you want?" 16 70
      ret=$?
  
      case $ret in
        0)
          break;;
        1)
          ;;
      esac

    fi
    
  fi

done


# VAULT MOUNTPOINT
if [ "$current_user" = "root" ]; then
  mountpoint_example="\nSuggested system-wide mountpoint location: /mnt/cryptovault"
else
  mountpoint_example="\nSuggested mountpoint location: ${HOME}/cryptovault"
fi

while true; do
  dialog --title "Mountpoint selection" --msgbox "\nOn the next screen select the location where you want the vault to be mounted when opened. 
If this is a system-wide vault, use a path under /mnt/. For a personal vault, select a mountpoint under a home directory.\n\n
NOTE: Use Up/Dn [arrow] to move to move the selector, SPACE to copy selected directory to the edit line, and ENTER to accept the current path in the edit box. 
To move to subdir/parent, add/remove \"/\" after the directory name on the edit line.\n\n
NOTE: If a non-existent path is entered, the directory/directories will be created. Existing but non-empty directories are not accepted. This directory can not be used for other purposes.\n\n
NOTE: Global locations (e.g. /mnt/mountdir) are set up for root access, while user-owned locations (e.g. /home/alice/mountdir) are set up for the owner of the parent dir (i.e. \"alice\" in this example).\n\n
${mountpoint_example}" 27 75

  MOUNTPOINT=$(dialog --title "Mountpoint selection" --dselect ${HOME}/ 16 60 2>&1 > /dev/tty)
  ret=$?

  #remove slash from the end if there is one
  MOUNTPOINT=${MOUNTPOINT%/}
  
  case $ret in
    0)
      ;;
    1)
      exit 1;;
  esac

  find_existing_parent mountpath_existing_parent $MOUNTPOINT
  find_dir_owner mountpath_owner $mountpath_existing_parent

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

  mountpoint_info=""
  confirm=false
  mountpoint_exists=true
  if [ "$MOUNTPOINT" = "$VAULTFILE_HOME" ]; then
    mountpoint_selection_info="Vault file path and the mountpoint cannot be the same directory; the mountpoint directory must always remain empty."
  else    
    if [ -d "$MOUNTPOINT" ]; then
      if [ "$(ls -A $MOUNTPOINT)" ]; then
        mountpoint_selection_info="This directory is not empty.\n\nSelect an empty directory, or create new."
      else
        mountpoint_selection_info="This directory exists and it is empty."
        confirm=true
      fi
    else
      mountpoint_owner_info=''
      if [ "$current_user" != "$mountpath_owner" ]; then
        if [ "$mountpath_owner" = "root" ]; then
          mountpoint_owner_info="The selected mountpoint path is a system location, and will be owned by the root user.\n\n"
        else
          mountpoint_owner_info="The selected location is owned by user \"$mountpath_owner\", and the mountpoint will be made private to that user.\n\n"
        fi
      fi

      mountpoint_selection_info="This directory does not exist; it will be created."
      confirm=true
      mountpoint_exists=false
    fi
  fi

  if [ "$confirm" = "true" ]; then
    dialog --title "Confirm selected mountpoint" --yesno "\n${different_owners_WARNING}You selected mountpoint path:\n\n${MOUNTPOINT}\n\n${mountpoint_selection_info}\n\n${mountpoint_owner_info}Is this what you want?" 22 75
    ret=$?
  
    case $ret in
      0)
        break;;
      1)
        ;;
    esac
  
  else
    dialog --title "ERROR" --msgbox "\n$mountpoint_selection_info" 14 50
  fi
  
done

dialog --title "Confirm to proceed" --yesno "\nIf you proceed, the encrypted vault will be created with the following parameters you have entered:\n\n
Vault filesystem: ${CRYPTOVAULT_FS}\n
Vault size: ${VAULTSIZEVAL}${VAULTSIZEUNIT}\n
Vault label: ${CRYPTOVAULT_LABEL}\n
Vault file path: ${VAULTFILE_FQFN} (owned by $vaultpath_owner)\n
Vault mount path: ${MOUNTPOINT} (owned by $mountpath_owner)\n\n
If the values are not correct, cancel and run the script again.\n\nDo you want to proceed?" 22 80
ret=$?
  
case $ret in
  0)
    ;;
  1)
    clear && echo -e "\n\e${BWhite}\e${On_Red} SCRIPT WAS CANCELLED \e${Color_Off}\n\n" && exit 1;;
esac

# MAIN LOGIC: CREATE PATHS AND THE DISK ======================================

clear 

echo

trap - INT TERM
trap cleanup INT TERM

executing="\e${BGreen}EXECUTING\e${Color_Off}"
if [ "$im_root" = "false" ]; then
  elevated=" \e${Black}\e${On_Green}ELEVATED\e${Color_Off}"
else
  elevated=''
fi

# create vault path
vaultpath_creation_error="false"
if [ "$vaultpath_exists" = "false" ]; then
  echo -e "\e${BIWhite}Creating vault path...\e${Color_Off}"
  executable="mkdir -p $VAULTFILE_HOME"
  if [ "$vaultpath_owner" = "$current_user" ]; then
    echo -e "$executing: $executable"
    eval $executable 2>/dev/null
    if [ $? -ne 0 ]; then
      vaultpath_creation_error="true"
    fi    
  else
    echo -e "${executing}$elevated (as $vaultpath_owner): $executable"
    sudoitas _ret $vaultpath_owner $executable
    if [ ${_ret} -ne 0 ]; then
      vaultpath_creation_error="true"
    fi
  fi
 
  # test vaultpath creation
  if [ "$vaultpath_creation_error" = "true" ] ||
     [ ! -d "$VAULTFILE_HOME" ]; then
    echo -e "\e${BWhite}\e${On_Red}Could not create vault path \"${VAULTFILE_HOME}\". Unable to proceed.\e${Color_Off}"
    cleanup
  fi
fi

echo

# create blank vault container file
vaultfile_creation_error="false"
echo -e "\e${BIWhite}Creating blank vault container file...\e${Color_Off}"
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
   [ ! -f "${VAULTFILE_FQFN}" ]; then
  echo -e "\e${BWhite}\e${On_Red}Could not create vault container file \"${VAULTFILE_FQFN}\". Unable to proceed.\e${Color_Off}"
  cleanup
fi

echo

# create mountpoint path
mountpoint_creation_error="false"
if [ "$mountpoint_exists" = "false" ]; then
  echo -e "\e${BIWhite}Creating the mountpoint (an empty directory)...\e${Color_Off}"
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
    echo -e "\e${BWhite}\e${On_Red}Could not create the mountpoint at \"${MOUNTPOINT}\". Unable to proceed.\e${Color_Off}"
    cleanup
  fi
fi

echo

# format the container
echo -e "\e${BIWhite}Formatting the container with encrypted LUKS filesystem...\e${Color_Off}"
echo -e "${executing}$elevated: cryptsetup luksFormat -q ${VAULTFILE_FQFN}"

if [ "$im_root" = "false" ]; then
  if ! sudo -n true 2>/dev/null; then 
    echo -e "\e${IYellow}This operation may require you to re-enter your sudo password below:\e${Color_Off}"
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
  echo -e "\e${BWhite}\e${On_Red}Could not format the vault container with LUKS at \"${VAULTFILE_FQFN}\". Unable to proceed.\e${Color_Off}"
  cleanup
fi

echo

# set up the loop device
echo -e "\e${BIWhite}Setting up the loop device...\e${Color_Off}"
if ! sudo -n true 2>/dev/null; then 
  echo -e "\e${IYellow}This operation may require you to re-enter your sudo password below:\e${Color_Off}"
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
  echo -e "\e${BWhite}\e${On_Red}Could not set up the loop device. Unable to proceed.\e${Color_Off}"
  cleanup
fi

echo

# open the mapped loop device (req. selected encryption password)
echo -e "\e${BIWhite}Opening the mapped device...\e${Color_Off}"
executable="cryptsetup luksOpen $loopdev ${CRYPTOVAULT_LABEL}"
echo -e "${executing}$elevated: $executable"
echo -e "\e${IYellow}The encrypted device is being opened. Please enter below the encryption password\nyou selected earlier in the process (NOTE: typed characters will not echo).\e${Color_Off}"
sudoit _ret $executable

if [ ${_ret} -ne 0 ]; then
  echo -e "\e${BWhite}\e${On_Red}Could not open the loop device (are you sure you entered the decryption password correctly?). Unable to proceed.\e${Color_Off}"
  cleanup
fi

echo

# create and mount the filesystem
echo -e "\e${BIWhite}Creating the ${CRYPTOVAULT_FS} filesystem...\e${Color_Off}"
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
  echo -e "\e${BWhite}\e${On_Red}Could not mount the crypto vault at  \"${MOUNTPOINT}\". Unable to proceed.\e${Color_Off}"
  cleanup
fi

if [ "$mountpath_owner" != "root" ]; then
  echo
  echo -e "\e${BIWhite}Setting the mountpoint permissions...\e${Color_Off}"
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
  echo "The utility script stubs in \"_stubs\" subdirectory are missing. Unable to proceed. Please make sure that you have not altered the cloned \"cryptovault\" repository, and try again!"
  cleanup 
fi

#TODO: Should these utility scripts perhaps be copied to the homedir of the user who owns the mountpoint ($mountpath_owner)?
#      mountpath_owner_home=$( getent passwd ${mountpath_owner} | cut -d: -f6 )
#      Or perhaps inquire the user where they want these placed (and made executable to)?

echo -e "\e${BIWhite}Generating command scripts...\e${Color_Off}"

CRYPTOVAULT_COMMANDDIR=$HOME/${CRYPTOVAULT_LABEL}-commands
mkdir $CRYPTOVAULT_COMMANDDIR

#TODO: File operation error checks

cp ${SCRIPT_DIR}/_stubs/mount-crypto ${CRYPTOVAULT_COMMANDDIR}/mount-${CRYPTOVAULT_LABEL}
cp ${SCRIPT_DIR}/_stubs/umount-crypto ${CRYPTOVAULT_COMMANDDIR}/umount-${CRYPTOVAULT_LABEL}
cp ${SCRIPT_DIR}/_stubs/util-crypto ${CRYPTOVAULT_COMMANDDIR}/util-${CRYPTOVAULT_LABEL}

#TODO: Use a tempfile instead of 'sponge'? (It's not a system command but provided by 'moreutils' package)

if [ "$CRYPTOVAULT_FS" = "zfs" ]; then
  echo -e "#!/bin/bash\n
CRYPTOVAULT_FS=${CRYPTOVAULT_FS}
CRYPTOVAULT_FQFN=${VAULTFILE_FQFN}
CRYPTOVAULT_MOUNTPOINT=${MOUNTPOINT}
CRYPTOVAULT_LABEL=${CRYPTOVAULT_LABEL}
ZPOOL_ID=${zpool_id}\n" | cat - "${CRYPTOVAULT_COMMANDDIR}/mount-${CRYPTOVAULT_LABEL}" | sponge "${CRYPTOVAULT_COMMANDDIR}/mount-${CRYPTOVAULT_LABEL}"

else

  echo -e "#!/bin/bash\n
CRYPTOVAULT_FS=${CRYPTOVAULT_FS}
CRYPTOVAULT_FQFN=${VAULTFILE_FQFN}
CRYPTOVAULT_MOUNTPOINT=${MOUNTPOINT}
CRYPTOVAULT_LABEL=${CRYPTOVAULT_LABEL}\n" | cat - "${CRYPTOVAULT_COMMANDDIR}/mount-${CRYPTOVAULT_LABEL}" | sponge "${CRYPTOVAULT_COMMANDDIR}/mount-${CRYPTOVAULT_LABEL}"

fi
echo "Crypto vault mount script created at ${CRYPTOVAULT_COMMANDDIR}/mount-${CRYPTOVAULT_LABEL}"

echo -e "#!/bin/bash\n
CRYPTO_FQFN=${VAULTFILE_FQFN}
CRYPTO_MOUNTPOINT=${MOUNTPOINT}
CRYPTO_LABEL=${CRYPTOVAULT_LABEL}
ZPOOL_ID=${zpool_id}\n" | cat - "${CRYPTOVAULT_COMMANDDIR}/umount-${CRYPTOVAULT_LABEL}" | sponge "${CRYPTOVAULT_COMMANDDIR}/umount-${CRYPTOVAULT_LABEL}"
echo "Crypto vault umount script created at ${CRYPTOVAULT_COMMANDDIR}/umount-${CRYPTOVAULT_LABEL}"

echo -e "#!/bin/bash\n
CRYPTOVAULT_FS=${CRYPTOVAULT_FS}
CRYPTO_FQFN=${VAULTFILE_FQFN}
CRYPTO_MOUNTPOINT=${MOUNTPOINT}
CRYPTO_LABEL=${CRYPTOVAULT_LABEL}
ZPOOL_ID=${zpool_id}\n" | cat - "${CRYPTOVAULT_COMMANDDIR}/util-${CRYPTOVAULT_LABEL}" | sponge "${CRYPTOVAULT_COMMANDDIR}/util-${CRYPTOVAULT_LABEL}"
echo "Crypto vault utility script created at ${CRYPTOVAULT_COMMANDDIR}/util-${CRYPTOVAULT_LABEL}"

echo

#TODO: set ownership & make executable for the commanddir & the commands (above)


# MAIN LOGIC: PROCESS COMPLETED; WRAPPING UP =================================

# confirm to keep the vault (option to fully bail out)
echo -n "Crypto vault \"${CRYPTOVAULT_LABEL}\" has been created. Keep this new vault (y/n)? "
old_stty_cfg=$(stty -g)
stty raw -echo
answer=$( while ! head -c 1 | grep -i '[yn]' ;do true ;done )
stty $old_stty_cfg
if echo "$answer" | grep -iq "^n" ; then
  echo
  echo "Abandoning the created crypt disk."
  cleanup
else

  # deactivate 'cleanup' trap (INT TERM)
  trap - INT TERM
  # activate 'cleanup nodelete' trap (INT TERM)
  trap 'echo && echo "Closing the crypto vault." && cleanup nodelete' INT TERM

  dialog --title "Lock/unmount the new crypto vault?" --yesno "\nDo you want to leave the newly created crypto vault mounted and unlocked at \"${MOUNTPOINT}\"?\n\n
You can unmount/lock and remount/unlock the crypto vault at any time using the \"mount-${CRYPTOVAULT_LABEL}\" and \"umount-${CRYPTOVAULT_LABEL}\" scripts which have been created at \"${CRYPTOVAULT_COMMANDDIR}\"." 20 70
  _ret=$?
  
  case ${_ret} in
    0)
      clear && echo && echo "Leaving the crypto vault open at ${MOUNTPOINT}" && exit_info;;
    1)
      clear && echo && echo "Closing the crypto vault." && cleanup nodelete;;
  esac

fi