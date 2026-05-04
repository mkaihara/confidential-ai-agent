ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
PYTHON       ?= $(shell which python3)

.PHONY: all sgx clean

all: sgx

hello.manifest: hello.manifest.template
	gramine-manifest \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=$(PYTHON) \
		$< $@

hello.manifest.sgx hello.sig: hello.manifest
	gramine-sgx-sign \
		--manifest hello.manifest \
		--output hello.manifest.sgx

sgx: hello.manifest.sgx hello.sig

clean:
	rm -f hello.manifest hello.manifest.sgx hello.sig hello.token
