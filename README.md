# CPE
Common Platform Enumeration (CPE) is a standardized method of describing and identifying classes of applications, operating systems, and hardware devices present among an enterprise's computing assets. CPE does not identify unique instantiations of products on systems, CPE identifies abstract classes of products.

This repository analyse the security standard CPE and generate from source a data frame and transform in a clear data frame.

# cpe.R
Fichero en R que descarga el data feed, lo trata y lo convierte en el data frame bien pulido

# CPE.md
Documento de analisis del estandard de seguridad CPE y sus diferentes elementos en el schema

# Variables interesantes

Como hemos ido hablando, nos vamos a quedar con las siguientes variables:

* cpe.23
* vendor
* part
* product
* sw_edition
* target_hw
* target_sw
* version
