DIR_TOP=
DIR_PDF=$(DIR_TOP)
DIR_DOC=$(DIR_TOP)
ifndef GFM2PDF_HOME
$(error The environment variable GFM2PDF_HOME is not set. Please set it and try again.)
endif
# Look of the PDF, e.g. the theme of aspera-cli: build/doc/pdf_theme
ifndef GFM2PDF_THEME
$(error The environment variable GFM2PDF_THEME is not set. Please set it and try again.)
endif
# gfm2pdf-toolchain 1.x: themes, options of a document in a comment <!-- gfm2pdf
GFM2PDF_VERSION_REQUIRED ?= >= 1.0.0.pre, < 2
include $(GFM2PDF_HOME)/pandoc.mak

ALL_PDFS=README.pdf

all:: $(ALL_PDFS)

#$(eval $(call markdown_to_pdf,$(DIR_TOP)%.md,$(DIR_PDF)%.pdf))

clean:
	rm -f $(ALL_PDFS)
