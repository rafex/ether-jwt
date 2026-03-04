#!/usr/bin/env bash

# Script para generar un secreto HMAC seguro para JWT (HS256)
# Uso: ./generate-jwt-hmac-secret.sh -d <directorio> -n <nombre_base> -b <bytes>
# Ejemplo: ./generate-jwt-hmac-secret.sh -d config/keys -n jwt -b 48

set -euo pipefail

dir="."
name="jwt"
bytes=48

usage() {
  echo "Uso: $0 -d <directorio> -n <nombre_base> -b <bytes>"
  echo "  -d  Directorio de salida (default: .)"
  echo "  -n  Nombre base del archivo (default: jwt)"
  echo "  -b  Cantidad de bytes aleatorios antes de Base64 (default: 48)"
  exit 1
}

while getopts "d:n:b:" opt; do
  case ${opt} in
    d) dir="$OPTARG" ;;
    n) name="$OPTARG" ;;
    b) bytes="$OPTARG" ;;
    *) usage ;;
  esac
done

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: openssl no está instalado o no está en PATH." >&2
  exit 1
fi

if ! [[ "$bytes" =~ ^[0-9]+$ ]] || [ "$bytes" -lt 32 ]; then
  echo "Error: -b debe ser un número entero >= 32." >&2
  exit 1
fi

mkdir -p "$dir"

secret_file="$dir/${name}_hmac.secret"

umask 077
secret_value="$(openssl rand -base64 "$bytes" | tr -d '\n')"
printf '%s\n' "$secret_value" > "$secret_file"

# Archivo de ayuda opcional para configuración por properties
properties_file="$dir/${name}_hmac.properties"
printf 'jwt.secret=%s\n' "$secret_value" > "$properties_file"

cat <<MSG
Secreto HMAC generado correctamente:

- Archivo secreto: $secret_file
- Archivo properties: $properties_file

Puedes configurarlo así:

export JWT_SECRET='$secret_value'

O usando properties:

jwt.secret=$secret_value
MSG
