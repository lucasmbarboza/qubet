from bcc import BPF
import ctypes as ct
import sys
import subprocess
import cipher_tools

# Localize o caminho da libssl usada no container
LIBSSL_PATH = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1"

# Obtenha o PID do nginx no host


# def get_nginx_pid():
#     out = subprocess.check_output(["pgrep", "-n", "nginx"]).decode().strip()
#     return int(out)


nginx_pid = cipher_tools.get_container_pid('nginx')
print(f"[+] NGINX PID: {nginx_pid}")

# BPF Program: intercepta SSL_get_current_cipher()
bpf_program = """
#include <uapi/linux/ptrace.h>

struct SSL_CIPHER {
    int valid;
    const char *name;
};

struct cipher_event_t {
    u64 ts;
    u32 pid;
    char name[128];
};

BPF_PERF_OUTPUT(events);

int trace_ssl_get_current_cipher(struct pt_regs *ctx) {
    struct SSL_CIPHER *cipher = (struct SSL_CIPHER *) PT_REGS_RC(ctx);
    struct cipher_event_t event = {};

    event.ts = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_probe_read_user_str(&event.name, sizeof(event.name), cipher->name);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

b = BPF(text=bpf_program)

# Anexa a função SSL_get_current_cipher da libssl do processo NGINX
b.attach_uprobe(
    name=LIBSSL_PATH,
    sym="SSL_get_current_cipher",
    fn_name="trace_ssl_get_current_cipher",
    pid=nginx_pid,
)

# Callback


def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"[PID {event.pid}] Cipher suite usada: {event.name.decode('utf-8')}")


# Escuta os eventos
print("[*] Aguardando chamadas de SSL_get_current_cipher()...")
b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nEncerrado.")
    pass