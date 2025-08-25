'''
GET CIPHERS FROM OPEN CSSL
'''
import subprocess as s

# TODO: DISCOVER IF OPENSSL IS BEING USED


def get_ciphers() -> list[str]:
    ''' This function tries to use openssl to extract all avaliables ciphers'''
    ciphers = None
    try:
        # GET OPENSSLL VERSION
        _CMD = ['openssl', 'version']
        r = s.run(_CMD, check=True, capture_output=True, text=True, )
        print(r.stdout)
        if 'OpenSSL' in r.stdout:
            _CMD = ['openssl', 'ciphers']
            r = s.run(_CMD, check=True, capture_output=True, text=True)
            ciphers = r.stdout
    except Exception as e:
        print(e)

    if ciphers is None:
        # EXTRACTED FROM OPENSSL VERSION 3.0.15
        ciphers = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:RSA-PSK-AES256-GCM-SHA384:DHE-PSK-AES256-GCM-SHA384:RSA-PSK-CHACHA20-POLY1305:DHE-PSK-CHACHA20-POLY1305:ECDHE-PSK-CHACHA20-POLY1305:AES256-GCM-SHA384:PSK-AES256-GCM-SHA384:PSK-CHACHA20-POLY1305:RSA-PSK-AES128-GCM-SHA256:DHE-PSK-AES128-GCM-SHA256:AES128-GCM-SHA256:PSK-AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-AES256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-CBC-SHA384:DHE-PSK-AES256-CBC-SHA384:RSA-PSK-AES256-CBC-SHA:DHE-PSK-AES256-CBC-SHA:AES256-SHA:PSK-AES256-CBC-SHA384:PSK-AES256-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:RSA-PSK-AES128-CBC-SHA256:DHE-PSK-AES128-CBC-SHA256:RSA-PSK-AES128-CBC-SHA:DHE-PSK-AES128-CBC-SHA:AES128-SHA:PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA'

    cipher_list = ciphers.split(':')

    return cipher_list


def get_path_libssl() -> str:
    '''Finds libssl path'''
    path_libssl = None
    try:
        _CMD = ['ldconfig', '-p']
        output = s.check_output(_CMD, text=True)
        lines = output.splitlines()
        for line in lines:
            if "libssl.so" in line:
                path_libssl = line.split(' => ')[1]
    except Exception as e:
        print('Erro: ', e)
    return path_libssl


def get_container_pid(service_name: str):
    '''GET MONITORED CONTAINER PROCCESS PID'''
    pid = None
    try:
        _CMD = ['pgrep', '-n', service_name]
        r = s.run(_CMD, check=True, capture_output=True, text=True)
        pid = int(r.stdout.strip())
    except Exception as e:
        print('Erro: ', e)
    return pid

print(get_path_libssl())
print(get_ciphers())
print(get_container_pid('bash'))