#First of all, we install all package required
install.packages("rvest")
install.packages("xml2")
install.packages("XML")

#Create a temp file to download de dictionary
tmpv <- tempfile()
raw.file2 <- "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
download.file(url = raw.file, destfile = tmpv)

#Dump the raw data in an xml format file
doc <- xml2::read_xml(tmpv)

#Create the data frame
cpes <- data.frame(title = xml2::xml_text(xml2::xml_find_all(doc, "//*[cpe-23:cpe23-item]/*[@xml:lang='en-US'][1]")),
cpe.22 = xml2::xml_text(xml2::xml_find_all(doc, "//cpe-23:cpe23-item/@name")),
cpe.23 = xml2::xml_text(xml2::xml_find_all(doc, "//*[cpe-23:cpe23-item]/*/@name")),
stringsAsFactors = F)
new.cols <- c("std", "std.v", "part", "vendor", "product",
"version", "update", "edition", "language", "sw_edition",
"target_sw", "target_hw", "other")
