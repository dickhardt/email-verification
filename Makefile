LIBDIR := lib
CHARTER := charter-ietf-evp-00-00
GHPAGES_EXTRA := $(CHARTER).html
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b main https://github.com/martinthomson/i-d-template $(LIBDIR)
endif

# Editor's copy of the draft WG charter (not an Internet-Draft).
latest:: $(CHARTER).html
$(CHARTER).html: $(CHARTER).md charter-head.inc
	$(mmark) -html -head charter-head.inc $< | sed -e "s,<title></title>,<title>EVP WG Draft Charter</title>," > $@
