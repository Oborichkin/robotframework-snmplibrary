test: venv
	$(VENV)/pytest -vvv

RECEIVER = 127.0.0.1:1620
ENTERPRIZE_OID = 1.2.3.4.5.6
AGENT_ADDR = 127.0.0.1

v1-trap:
	snmptrap -v 1 -c public $(RECEIVER) '1.2.3.4.5.6' '127.0.0.1' 6 99 '55' 1.11.12.13.14.15 s "teststring"

v2c-trap:
	snmptrap -v 2c -c public $(RECEIVER) '' 1.3.6.1.4.1.8072.2.3.0.1 1.3.6.1.4.1.8072.2.3.2.1 i 123456

include Makefile.venv
Makefile.venv:
	curl \
		-o Makefile.fetched \
		-L "https://github.com/sio/Makefile.venv/raw/v2020.08.14/Makefile.venv"
	echo "5afbcf51a82f629cd65ff23185acde90ebe4dec889ef80bbdc12562fbd0b2611 *Makefile.fetched" \
		| sha256sum --check - \
		&& mv Makefile.fetched Makefile.venv