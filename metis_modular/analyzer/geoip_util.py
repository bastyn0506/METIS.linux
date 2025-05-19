import geoip2.database

reader = geoip2.database.Reader(r'C:\Users\nakah\Desktop\metis\python\metis_modular\analyzer\GeoLite2-Country_20250404\GeoLite2-Country.mmdb')

def get_country(ip):
    try:
        response = reader.country(ip)
        return response.country.name
    except:
        return "Unknown"