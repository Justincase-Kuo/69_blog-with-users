import requests
from datetime import datetime


api_key = 'e6da71166e9e40fa98008b9a037a03a8'
api_url = 'https://api.openweathermap.org/data/2.5/weather?'

melissa_lat = 25.035248
melissa_lon = 121.50815
justin_lat = 24.13498
justin_lon = 120.66686


class Weather():
    def __init__(self):
        self.melissa_params = {
                        'appid': api_key,
                        'lat': melissa_lat,
                        'lon': melissa_lon,
                        'units': 'metric',
                        'lang': 'zh_tw',
                            }

        self.justin_params = {
                            'appid': api_key,
                            'lat': justin_lat,
                            'lon': justin_lon,
                            'units': 'metric',
                            'lang': 'zh_tw',
                        }

    def get_weather_data(self):

        weather_list = []

        for params in [self.melissa_params, self.justin_params]:
            response = requests.get(url=api_url, params=params)
            data = response.json()

            icon_id = data['weather'][0]['icon']
            icon = f'http://openweathermap.org/img/w/{icon_id}.png'

            weather_data = {
                'weather_title': data['weather'][0]['main'],
                'temp': int(data['main']['temp']),
                'temp_max': data['main']['temp_max'],
                'temp_min': data['main']['temp_min'],
                'weather_subtitle': data['weather'][0]['description'],
                'weather_icon': icon,
                'sunrise': datetime.fromtimestamp(data['sys']['sunrise']).strftime('%Y-%m-%d %H:%M:%S'),
                'sunset': datetime.fromtimestamp(data['sys']['sunset']).strftime('%Y-%m-%d %H:%M:%S'),
            }

            weather_list.append(weather_data)

        return weather_list


