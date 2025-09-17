import socket
import sys
import ipaddress
from ipwhois import IPWhois
import dns.resolver
import requests
import argparse
from datetime import datetime
import concurrent.futures
import json
import time
import os

# Конфигурация
DNS_RESOLVERS = [
    '8.8.8.8',        # Google DNS
    '1.1.1.1',        # Cloudflare DNS
    '9.9.9.9',        # Quad9 DNS
    '208.67.222.222', # OpenDNS
]
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 2

# Глобальная переменная для базы ASN
asn_database = {}

def load_asn_database():
    """Загружает базу ASN из файла."""
    global asn_database
    try:
        with open('asn_database.json', 'r', encoding='utf-8') as f:
            asn_database = json.load(f)
        print(f"Загружена база ASN: {len(asn_database)} записей")
    except FileNotFoundError:
        print("Файл asn_database.json не найден. Создана пустая база ASN.")
        asn_database = {}
    except Exception as e:
        print(f"Ошибка при загрузке базы ASN: {e}")
        asn_database = {}

def retry_request(func):
    """Декоратор для повторных попыток запросов."""
    def wrapper(*args, **kwargs):
        for attempt in range(MAX_RETRIES):
            try:
                result = func(*args, **kwargs)
                if result is not None:
                    return result
                elif attempt == MAX_RETRIES - 1:
                    print(f"Все {MAX_RETRIES} попытки не удались для {func.__name__}")
                    return None
            except (requests.exceptions.RequestException, Exception) as e:
                if attempt == MAX_RETRIES - 1:
                    print(f"Все {MAX_RETRIES} попытки не удались для {func.__name__}: {e}")
                    return None
                print(f"Попытка {attempt + 1}/{MAX_RETRIES} не удалась: {e}")
                time.sleep(RETRY_DELAY * (attempt + 1))
        return None
    return wrapper

@retry_request
def get_domain_ips(domain):
    """Получает IPv4-адреса домена с использованием multiple DNS-резолверов."""
    ips = set()
    
    for resolver_ip in DNS_RESOLVERS:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            answers = resolver.resolve(domain, 'A')
            for rdata in answers:
                ips.add(str(rdata))
            print(f"DNS {resolver_ip} вернул {len(answers)} IP-адресов")
        except Exception as e:
            print(f"Ошибка при запросе к DNS {resolver_ip}: {e}")
    
    return list(ips)

@retry_request
def get_cidr_from_rdap(ip):
    """Определяет CIDR через RDAP-запросы."""
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        
        # Пытаемся извлечь CIDR разными способами
        cidr = results.get('asn_cidr', None)
        if not cidr:
            network = results.get('network', {})
            cidr = network.get('cidr', None)
        
        if cidr:
            # Нормализуем CIDR
            net = ipaddress.ip_network(cidr, strict=False)
            result = str(net)
            print(f"Получен CIDR для {ip} через RDAP: {result}")
            return result
        else:
            result = f"{ip}/32"
            print(f"Не удалось определить CIDR для {ip}, используем: {result}")
            return result
            
    except Exception as e:
        print(f"Ошибка при выполнении RDAP-запроса для IP {ip}: {e}")
        result = f"{ip}/32"
        return result

@retry_request
def get_asn_info_from_ipinfo(asn):
    """Получает информацию об автономной системе через ipinfo.io API."""
    try:
        url = f"https://ipinfo.io/AS{asn}/json"
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            
            # Преобразуем формат ipinfo.io в наш формат
            formatted_data = {
                'name': data.get('name', ''),
                'prefixes': data.get('prefixes', [])
            }
            print(f"Получена информация об ASN {asn} из ipinfo.io")
            return formatted_data
        print(f"Не удалось получить информацию об ASN {asn} из ipinfo.io (статус: {response.status_code})")
        return None
    except Exception as e:
        print(f"Ошибка при запросе информации об ASN {asn} из ipinfo.io: {e}")
        return None

def get_asn_info(asn):
    """Получает информацию об автономной системе."""
    asn_str = str(asn)
    
    # Сначала проверяем локальную базу ASN
    if asn_str in asn_database:
        print(f"Использована локальная база для ASN {asn}")
        return asn_database[asn_str]
    
    # Затем запрашиваем из внешних источников
    print(f"Запрашиваем информацию об ASN {asn} из ipinfo.io")
    return get_asn_info_from_ipinfo(asn)

def aggregate_cidrs(cidr_list):
    """Агрегирует список CIDR-блоков."""
    if not cidr_list:
        return []

    networks = []
    for cidr in cidr_list:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            networks.append(net)
        except ValueError as e:
            print(f"Ошибка при обработке CIDR {cidr}: {e}")

    try:
        aggregated_nets = list(ipaddress.collapse_addresses(networks))
        result = [str(net) for net in aggregated_nets]
        print(f"Агрегировано {len(cidr_list)} CIDR в {len(result)} блоков")
        return result
    except Exception as e:
        print(f"Ошибка при агрегации сетей: {e}")
        return [str(net) for net in networks]

def cidr_to_keenetic_command(cidr):
    """Преобразует CIDR в команду для Keenetic .bat файла."""
    try:
        net = ipaddress.ip_network(cidr)
        network_address = net.network_address
        netmask = net.netmask
        
        # Форматируем команду для .bat файла Keenetic
        return f"route ADD {network_address} MASK {netmask} 0.0.0.0"
    except ValueError as e:
        print(f"Ошибка преобразования CIDR {cidr} для Keenetic: {e}")
        return None

def main(domain):
    print(f"🔍 Анализ домена: {domain}")
    print("=" * 50)

    # Загружаем базу ASN
    load_asn_database()

    # 1. Получаем IP-адреса домена с multiple DNS
    ips = get_domain_ips(domain)
    if not ips:
        print("Не удалось найти IP-адреса для указанного домена.")
        return

    print(f"Найдены IP-адреса: {', '.join(ips)}")

    # 2. Для каждого IP определяем CIDR (параллельно)
    cidrs_found = set()
    asn_set = set()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Получаем CIDR через RDAP
        future_to_ip = {executor.submit(get_cidr_from_rdap, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                cidr = future.result()
                if cidr:
                    cidrs_found.add(cidr)
            except Exception as e:
                print(f"Ошибка при обработке IP {ip}: {e}")

    # 3. Расширенный поиск: получаем информацию об ASN
    print("\n🔎 Расширенный поиск: анализ автономных систем")
    asn_cidrs = set()
    
    # Получаем ASN для каждого CIDR
    for cidr in cidrs_found:
        try:
            net = ipaddress.ip_network(cidr)
            ip = str(net.network_address)
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=1)
            asn = results.get('asn', None)
            if asn:
                asn_set.add(asn)
                print(f"Найден ASN {asn} для CIDR {cidr}")
            else:
                print(f"Не удалось определить ASN для CIDR {cidr}")
        except Exception as e:
            print(f"Ошибка при получении ASN для CIDR {cidr}: {e}")
    
    # Для каждого ASN получаем все префиксы
    for asn in asn_set:
        asn_info = get_asn_info(asn)
        if asn_info and 'prefixes' in asn_info:
            for prefix in asn_info['prefixes']:
                try:
                    net = ipaddress.ip_network(prefix)
                    if net.version == 4:  # Только IPv4
                        asn_cidrs.add(prefix)
                        print(f"Добавлен префикс {prefix} для ASN {asn}")
                except ValueError as e:
                    print(f"Ошибка обработки префикса {prefix} для ASN {asn}: {e}")
                    continue
        else:
            print(f"Не удалось получить информацию о префиксах для ASN {asn}")
    
    cidrs_found.update(asn_cidrs)
    print(f"Найдено дополнительных CIDR через ASN: {len(asn_cidrs)}")

    # 4. Агрегируем CIDR-блоки
    aggregated_cidrs = aggregate_cidrs(list(cidrs_found))

    # 5. Форматируем вывод для разных систем
    amneziawg_allowed_ips = ", ".join(aggregated_cidrs)

    keenetic_commands = []
    for cidr in aggregated_cidrs:
        command = cidr_to_keenetic_command(cidr)
        if command:
            keenetic_commands.append(command)

    # 6. Сохраняем результаты в файлы
    current_date = datetime.now().strftime("%Y-%m-%d")
    filename_amnezia = f"{domain}_amneziawg_{current_date}.txt"
    filename_keenetic = f"{domain}_keenetic_{current_date}.bat"

    try:
        # Файл для AmneziaWG
        with open(filename_amnezia, 'w', encoding='utf-8') as f:
            f.write(amneziawg_allowed_ips)
        print(f"\n✅ Результаты для AmneziaWG сохранены в файл: {filename_amnezia}")

        # .bat файл для Keenetic (только команды без комментариев)
        with open(filename_keenetic, 'w', encoding='utf-8') as f:
            for command in keenetic_commands:
                f.write(command + "\n")
        
        print(f"✅ Результаты для Keenetic сохранены в файл: {filename_keenetic}")
        print("💡 Файл .bat готов для импорта в роутер Keenetic")

    except IOError as e:
        print(f"Ошибка при записи в файл: {e}")
        return

    # 7. Выводим статистику
    print("\n" + "="*50)
    print(f"СТАТИСТИКА ДЛЯ ДОМЕНА: {domain}")
    print("="*50)
    print(f"Найдено IP-адресов: {len(ips)}")
    print(f"Найдено CIDR-блоков до агрегации: {len(cidrs_found)}")
    print(f"CIDR-блоков после агрегации: {len(aggregated_cidrs)}")
    print(f"Сокращение: {len(cidrs_found) - len(aggregated_cidrs)} блоков")
    print(f"Найдено автономных систем (ASN): {len(asn_set)}")
    print(f"ASN: {', '.join(str(asn) for asn in asn_set)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Определение CIDR-блоков для домена.')
    parser.add_argument('domain', type=str, help='Домен для анализа (например, example.com)')
    args = parser.parse_args()

    main(args.domain)