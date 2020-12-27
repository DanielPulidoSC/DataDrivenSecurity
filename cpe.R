#First of all, we install all package required
install.packages("rvest")
install.packages("xml2")
install.packages("XML")

#Create a temp file to download de dictionary
tmpv <- tempfile()
raw.file <- "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
download.file(url = raw.file, destfile = tmpv)

#Dump the raw data in an xml format file
doc <- xml2::read_xml(tmpv)

#Create the data frame
cpes <- data.frame(title = xml2::xml_text(xml2::xml_find_all(doc, "//*[cpe-23:cpe23-item]/*[@xml:lang='en-US'][1]")),
cpe.22 = xml2::xml_text(xml2::xml_find_all(doc, "//cpe-23:cpe23-item/@name")),
cpe.23 = xml2::xml_text(xml2::xml_find_all(doc, "//*[cpe-23:cpe23-item]/*/@name")),
stringsAsFactors = F)
#Define the columns of the data frame
new.cols <- c("std", "std.v", "part", "vendor", "product",
"version", "update", "edition", "language", "sw_edition",
"target_sw", "target_hw", "other")
#Replace backslashes by semicolon
cpes$cpe.23 <- stringr::str_replace_all(cpes$cpe.23, "\\\\:",";")
#Separate the data of cpe.23 (all items) in new.cols vector that contains each element separated 
#by semicolon and not removing the input data from output dataframe
cpes <- tidyr::separate(data = cpes, col = "cpe.23", into = new.cols, sep = ":", remove = F)
#Select colums std and std.v from cpes data frame and remove from df because all have the same value
cpes <- dplyr::select(.data = cpes, -std, -std.v)
#Convert important elements of dataframe in factors to operate on them
cpes$vendor <- as.factor(cpes$vendor)
cpes$part <- as.factor(cpes$part)
cpes$product <- as.factor(cpes$product)
cpes$sw_edition <- as.factor(cpes$sw_edition)
cpes$target_hw <- as.factor(cpes$target_hw)
cpes$target_sw <- as.factor(cpes$target_sw)
cpes$version <- as.factor(cpes$version)
#Finally, put all relevant elements in a vector
df_final <- cpes %>% select(product,version,vendor,part,sw_edition,target_hw,target_sw)
