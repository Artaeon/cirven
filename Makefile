SITE := site

.PHONY: serve size check

# local preview on http://127.0.0.1:8000
serve:
	python3 -m http.server 8000 --bind 127.0.0.1 --directory $(SITE)

# bytes per page: html + css + images it loads, raw and gzipped
size:
	@for f in $$(find $(SITE) -name '*.html' | sort); do \
	  deps="$$f $(SITE)/style.css $(SITE)/favicon.svg"; \
	  grep -q 'logo.svg' $$f && deps="$$deps $(SITE)/logo.svg"; \
	  raw=$$(cat $$deps | wc -c); gz=$$(for d in $$deps; do gzip -9c $$d; done | wc -c); \
	  printf '%-28s %6s B raw  %6s B gzip\n' $${f#$(SITE)/} $$raw $$gz; \
	done

# no scripts, no inline styles, no third-party requests
check:
	@! grep -rniP '<script|\sstyle=|\son[a-z]+=|(src|href)="https?://(?!www\.apache\.org)' --include='*.html' $(SITE) \
	  || (echo "check failed" && exit 1)
	@echo "check ok"
