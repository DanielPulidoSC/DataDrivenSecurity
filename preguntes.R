#Primer ordenem les variables d'indústria per les ocurrències
sort(table(incidents.data["industry"]))
#També ordenem les organitzacions
sort(table(incidents.data["org"]))
#Obtenim la columna mitre_attack
attacks <- dplyr::select(.data = incidents.data, mitre_attack)
