def extract_date_values(address):
    # Estrai i valori di day, month e year dall'indirizzo
    day = (address >> 24) & 0xFF  # Estrai il byte più significativo per il giorno
    month = (address >> 16) & 0xFF  # Estrai il byte successivo per il mese
    year = (address >> 0) & 0xFFFF  # Estrai i due byte meno significativi per l'anno

    return month, year, day

# Esempio di utilizzo della funzione
address_hex = 0xffffdda0
month, year, day = extract_date_values(address_hex)

print(f"Month: {month}, Year: {year}, Day: {day}")
print(f"Month: {str(month).encode()}, Year: {str(year).encode()}, Day: {str(day).encode()}")