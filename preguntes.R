#Primer ordenem les variables d'indústria per les ocurrències
sort(table(incidents.data["industry"]))
#També ordenem les organitzacions
sort(table(incidents.data["org"]))
#Obtenim la columna mitre_attack
attacks <- dplyr::select(.data = incidents.data, mitre_attack)
#o d'aquesta altra manera
mitre.attack <- incidents.data$mitre_attack
#Finalment, fotem la llista de dataframes en un sol dataframe
mitre.final = data.table::rbindlist(mitre.attack)
#o d'aquesta altra manera
mitre.final <- dplyr::bind_rows(mitre.attack)
