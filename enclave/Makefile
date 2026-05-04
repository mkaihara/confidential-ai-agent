ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
PYTHON       ?= $(shell which python3)

.PHONY: all sgx clean

all: sgx

enclave_llm.manifest: enclave_llm.manifest.template
	gramine-manifest \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=$(PYTHON) \
		$< $@

enclave_llm.manifest.sgx enclave_llm.sig: enclave_llm.manifest
	gramine-sgx-sign \
		--manifest enclave_llm.manifest \
		--output enclave_llm.manifest.sgx

sgx: enclave_llm.manifest.sgx enclave_llm.sig

clean:
	rm -f enclave_llm.manifest enclave_llm.manifest.sgx \
	      enclave_llm.sig enclave_llm.token \
	      hello.manifest hello.manifest.sgx hello.sig hello.token
