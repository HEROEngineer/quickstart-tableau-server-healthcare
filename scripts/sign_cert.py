import os
import subprocess
import shlex
import argparse

def get_version(version_path):
	with open(version_path, 'r') as f:
		version = f.readline().strip()
	return version

def generate_key(openssl_path, openssl_conf_path, private_key_name, bit_length=4096):
	cmd = '"%s" genrsa -out %s %s' % (openssl_path, private_key_name, bit_length)
	subprocess.run(shlex.split(cmd), env={'OPENSSL_CONF': openssl_conf_path})

def generate_csr(openssl_path, openssl_conf_path, private_key_name, csr_name):
	cmd = '"%s" req -new -key %s -out %s' % (openssl_path, private_key_name, csr_name)
	subprocess.run(shlex.split(cmd), env={'OPENSSL_CONF': openssl_conf_path})

def sign_cert(openssl_path, openssl_conf_path, private_key_name, csr_name, cert_name):
	cmd = '"%s" x509 -req -days 365 -in %s -signkey %s -out %s' % (openssl_path, csr_name, private_key_name, cert_name)
	subprocess.run(shlex.split(cmd), env={'OPENSSL_CONF': openssl_conf_path})

def main():
	parser = argparse.ArgumentParser()

	parser.add_argument('--version_path', type=str, required=True)
	parser.add_argument('--install_dir', type=str, required=True)
	parser.add_argument('--ssl_prefix', type=str, default='tableau_quickstart')

	args = parser.parse_args()

	version_path = args.version_path
	install_dir = args.install_dir
	ssl_prefix = args.ssl_prefix

	# First get the version
	version = get_version(version_path)

	# Next create a ssl directory
	ssl_dir = os.path.join(install_dir, 'ssl')
	os.mkdir(ssl_dir)

	# Get paths for openssl conf and binary
	openssl_conf_path = os.path.join(install_dir, 'packages', 'apache.%s' % version, 'conf', 'openssl.cnf')
	openssl_path = os.path.join(install_dir, 'packages', 'apache.%s' % version, 'bin', 'openssl.exe')

	# generate key
	private_key_name = ssl_prefix + '.key'
	generate_key(openssl_path, openssl_conf_path, private_key_name)

	# generate csr
	csr_name = ssl_prefix + '.csr'
	generate_csr(openssl_path, openssl_conf_path, private_key_name, csr_name)

	# sign cert
	cert_name = ssl_prefix + '.crt'
	sign_cert(openssl_path, openssl_conf_path, private_key_name, csr_name, cert_name)
if __name__ == "__main__":
	main()
