DIR_TOP=
DIR_PDF=$(DIR_TOP)
DIR_DOC=$(DIR_TOP)
ifndef DIR_PANDOC
$(error The environment variable DIR_PANDOC is not set. Please set it and try again.)
endif
include $(DIR_PANDOC)pandoc.mak

ALL_PDFS=README.pdf

all:: $(ALL_PDFS)

#$(eval $(call markdown_to_pdf,$(DIR_TOP)%.md,$(DIR_PDF)%.pdf))

clean:
	rm -f $(ALL_PDFS)
