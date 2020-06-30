DEBUG ?= 0

main:
	@./scripts/init.sh $(DEBUG)

kernel:
	@./scripts/build_kernel.sh

clean:
	@$(MAKE) --no-print-directory -C daemon clean
	@$(MAKE) --no-print-directory -C libcitadel clean
	@$(MAKE) --no-print-directory -C userspace_demo clean
