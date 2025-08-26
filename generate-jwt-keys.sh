#!/usr/bin/env bash

# Script para generar par de claves RSA en PEM (PKCS#8 privado y X.509 público)
# Uso: ./generate-jwt-keys.sh -d <directorio> -n <nombre_base>
# Ejemplo: ./generate-jwt-keys.sh -d config/keys -n jwt

set -e

# Valores por defecto
dir="."
name="jwt"

usage() {
  echo "Uso: $0 -d <directorio> -n <nombre_base>"
  exit 1
}

while getopts "d:n:" opt; do
  case ${opt} in
    d) dir="$OPTARG" ;;    
    n) name="$OPTARG" ;;    
    *) usage ;;    
  esac
done

# Crear directorio si no existe
mkdir -p "$dir"

# Rutas de archivos
priv_pem="$dir/${name}_private.pem"
pub_pem="$dir/${name}_public.pem"

# Generar clave privada RSA 2048 bits en formato PKCS#8 PEM
openssl genpkey -algorithm RSA -out "$priv_pem" -pkeyopt rsa_keygen_bits:2048 \
    && echo "Clave privada RSA generada en $priv_pem"

# Extraer clave pública en formato X.509 PEM
openssl rsa -pubout -in "$priv_pem" -out "$pub_pem" \
    && echo "Clave pública RSA generada en $pub_pem"

echo "Generación de claves completada. Configura jwt.properties con:

privateKeyPath=$priv_pem
publicKeyPath=$pub_pem
"