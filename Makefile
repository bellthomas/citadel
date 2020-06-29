
main:
	@./scripts/init.sh
	
clean:
	@$(MAKE) --no-print-directory -C daemon clean
	@$(MAKE) --no-print-directory -C libcitadel clean
	@$(MAKE) --no-print-directory -C userspace_demo clean
