all: dnsinject dnsdetect

dnsinject: dnsinject.c
	@echo "Generating dnsinject executable"
	gcc dnsinject.c -o dnsinject -lpcap

dnsdetect: dnsdetect.c
	@echo "Generating dnsdetect executable"
	gcc dnsdetect.c -o dnsdetect -lpcap

clean:
	@echo "Cleaning dnsinject and dnsdetect executable"
	rm -f dnsinject
	rm -f dnsdetect
