#!/usr/bin/env sh

qcloud_API="https://cns.api.qcloud.com/v2/index.php"

#Qcloud_Secret_Id="LTqIA87hOKdjevsf5"
#Qcloud_Secret_Key="0p5EYueFNq501xnCPzKNbx6K51qPH2"

#Usage: dns_qcloud_add   _acme-challenge.www.domain.com   "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_qcloud_add() {
  fulldomain=$1
  txtvalue=$2

  Qcloud_Secret_Id="${Qcloud_Secret_Id:-$(_readaccountconf_mutable Qcloud_Secret_Id)}"
  Qcloud_Secret_Key="${Qcloud_Secret_Key:-$(_readaccountconf_mutable Qcloud_Secret_Key)}"
  if [ -z "$Qcloud_Secret_Id" ] || [ -z "$Qcloud_Secret_Key" ]; then
    Qcloud_Secret_Id=""
    Qcloud_Secret_Key=""
    _err "You don't specify Qcloud_Secret_Id and Qcloud_Secret_Key yet."
    return 1
  fi

  #save the api key and secret to the account conf file.
  _saveaccountconf_mutable Qcloud_Secret_Id "$Qcloud_Secret_Id"
  _saveaccountconf_mutable Qcloud_Secret_Key "$Qcloud_Secret_Key"

  _check_exist_query "pwpwpwpwpwpwpwpwpwpw.pw" "_acme-challenge"
  _qcloud_rest "Check exist records"
  _err "$response"
  return 1

  _debug "First detect the root zone"
  if ! _get_root "$fulldomain"; then
    return 1
  fi

  _debug "Add record"
  _add_record_query "$_domain" "$_sub_domain" "$txtvalue" && _qcloud_rest "Add record"
}

dns_qcloud_rm() {
  fulldomain=$1
  txtvalue=$2
  Qcloud_Secret_Id="${Qcloud_Secret_Id:-$(_readaccountconf_mutable Qcloud_Secret_Id)}"
  Qcloud_Secret_Key="${Qcloud_Secret_Key:-$(_readaccountconf_mutable Qcloud_Secret_Key)}"

  _debug "First detect the root zone"
  if ! _get_root "$fulldomain"; then
    return 1
  fi

  _clean
}

####################  Private functions below ##################################

_get_root() {
  domain=$1
  i=2
  p=1
  while true; do
    h=$(printf "%s" "$domain" | cut -d . -f $i-100)
    if [ -z "$h" ]; then
      #not valid
      return 1
    fi

    _describe_records_query "$h"
    if ! _qcloud_rest "Get root"; then
      return 1
    fi

    if _contains "$response" "Success"; then
      _sub_domain=$(printf "%s" "$domain" | cut -d . -f 1-$p)
      _debug _sub_domain "$_sub_domain"
      _domain="$h"
      _debug _domain "$_domain"
      return 0
    fi
    p="$i"
    i=$(_math "$i" + 1)
  done
  return 1
}

_qcloud_rest() {
  _debug "POSTcns.api.qcloud.com/v2/index.php?$query"
  signature=$(printf "%s" "POSTcns.api.qcloud.com/v2/index.php?$query" | _hmac "sha1" "$(printf "$Qcloud_Secret_Key" | _hex_dump | tr -d " ")" | _base64)
  signature=$(_urlencode "$signature")

  _debug "$query&Signature=$signature"

  url="$qcloud_API"

  if ! response="$(_post "$query&Signature=$signature" "$url")"; then
    _err "Error <$1>"
    return 1
  fi

  _debug response "$response"
}

_qcloud_nonce() {
  #_head_n 1 </dev/urandom | _digest "sha256" hex | cut -c 1-31
  #Not so good...
  date +"%s%N"
}

_urlencode() {
  _str="$1"
  _str_len=${#_str}
  _u_i=1
  while [ "$_u_i" -le "$_str_len" ]; do
    _str_c="$(printf "%s" "$_str" | cut -c "$_u_i")"
    case $_str_c in [a-zA-Z0-9.~_-])
      printf "%s" "$_str_c"
      ;;
    *)
      printf "%%%02X" "'$_str_c"
      ;;
    esac
    _u_i="$(_math "$_u_i" + 1)"
  done
}

_check_exist_query() {
  query=''
  query=$query'Action=RecordList'
  query=$query"&Nonce=$(_qcloud_nonce)"
  query=$query'&SecretId='$Qcloud_Secret_Id
  query=$query'&SignatureMethod=HmacSHA1'
  query=$query'&Timestamp='$(_timestamp)
  query=$query'&domain='$1
  query=$query'&recordType=TXT'
  query=$query'&subDomain='$2
}

_add_record_query() {
  query=''
  query=$query'Action=RecordCreate'
  query=$query"&Nonce=$(_qcloud_nonce)"
  query=$query'&SecretId='$Qcloud_Secret_Id
  query=$query'&SignatureMethod=HmacSHA1'
  query=$query'&Timestamp='$(_timestamp)
  query=$query'&domain='$1
  query=$query'&recordLine=默认'
  query=$query'&recordType=TXT'
  query=$query'&subDomain='$2
  query=$query'&value='$3
}

_delete_record_query() {
  query=''
  query=$query'&Action=RecordDelete'
  query=$query'&recordId='$1
  query=$query'&SignatureMethod=HmacSHA1'
  query=$query"&Nonce=$(_qcloud_nonce)"
  query=$query'&Timestamp='$(_timestamp)
}

_describe_records_query() {
  query=''
  query=$query'Action=RecordList'
  query=$query"&Nonce=$(_qcloud_nonce)"
  query=$query'&SecretId='$Qcloud_Secret_Id
  query=$query'&SignatureMethod=HmacSHA1'
  query=$query'&Timestamp='$(_timestamp)
  query=$query'&domain='$1
}

_clean() {
  _check_exist_query "$_domain" "$_sub_domain"
  if ! _qcloud_rest "Check exist records"; then
    return 1
  fi

  record_id="$(echo "$response" | tr '{' "\n" | grep "$_sub_domain" | grep "$txtvalue" | tr "," "\n" | grep RecordId | cut -d '"' -f 4)"
  _debug2 record_id "$record_id"

  if [ -z "$record_id" ]; then
    _debug "record not found, skip"
  else
    _delete_record_query "$record_id"
    _qcloud_rest "Delete record $record_id"
  fi

}

_timestamp() {
  date +%s
}

