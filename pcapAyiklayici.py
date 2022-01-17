import re,time
import matplotlib.pyplot as plt, numpy as np, pandas as pd

def dosyadanOkuyorum(dosyaAdi):
    dosyadanOkuma = time.time()
    with open(dosyaAdi) as flowDosya:
        flowHam = flowDosya.read()
    dosyaOkurken = time.time() - dosyadanOkuma
    print ('Dosyayı okurken geçen süre : ', str(dosyaOkurken))
    flowHamVeri = flowHam.split('\n')
    return flowHamVeri

#cikartilanlar = ()

# Wireshark output_csv kullanılarak yapılan ayrım

def WS_2_CSV(flowHam): #Wireshark CSV export çok Yön çok Port işleme bölümü.
    baslik = flowHam.pop(0)
    flowVeri = []
    protokoller = {}
    butunIslem = time.time()
    for sira, veri in enumerate(flowHam):
        if len(veri) == 0: continue
        ayrik = veri.split('","')
        zaman = ayrik[1].replace('"','')
        tekVeri = {}
        if sira % 250000 == 0:
            print (str(sira), ' veri ', str(time.time() - butunIslem), ' ms zamanda işlendi')
        if len(zaman) != 0 and ayrik[4].replace('"','') == 'TCP':
            tekVeri['zaman'] = zaman
            hususiyetler = re.findall(r'\w+=\d+',ayrik[6])
            aciklamalar = re.findall(r'\[.*?\]',ayrik[6])
            portlar = re.findall(r'\d+',ayrik[6])
            for hususiyet in hususiyetler:
                tekVeri[hususiyet.split('=')[0]] = hususiyet.split('=')[1]
                tekVeri['hedef'] = str(portlar[1])
                tekVeri['kaynak'] = str(portlar[2])
                tekVeri['aciklamalar'] = aciklamalar
            try:
                if portlar[1] not in protokoller:                
                    protokoller[str(portlar[1])] = {'ilk' : zaman, 'anlik': {'zaman' : [],'Seq' : [], 'bw' : []}, 'son': zaman, 'gonderilen': int(tekVeri['Seq']), 'bw': {}}
                else:
                    protokoller[str(portlar[1])]['son'] = zaman
                    protokoller[str(portlar[1])]['gonderilen'] = int(tekVeri['Seq'])
            except Exception as hata:
                print(hata, ' : ', ayrik[0], ' - ', ayrik[1], ' - ', ayrik[6])
            protokoller[str(portlar[1])]['anlik']['zaman'].append(zaman)
            protokoller[str(portlar[1])]['anlik']['Seq'].append(int(tekVeri['Seq']))
            protokoller[str(portlar[1])]['anlik']['bw'].append(int(tekVeri['Len']))
        if len(tekVeri) != 0: flowVeri += [tekVeri]
    butunIslem = time.time() - butunIslem
    return flowVeri, protokoller, butunIslem, baslik

def ek2senler(csvVeri,protokoller):#Wireshark CSV export çok Yön çok Port işleme bölümü. 
    onceki = {}
    onceki['Seq'] = 0
    onceki['zaman'] = 0
    onceki['bw'] = 0
    gonderilen = 0
    hedefPort = 0
    for protokol in protokoller:
        hedefPort = protokol if gonderilen < protokoller[protokol]['gonderilen'] else hedefPort
        if hedefPort in protokoller: gonderilen = protokoller[hedefPort]['gonderilen']
    protokoller[hedefPort]['bw'] = {}
    protokoller[hedefPort]['aktarilan'] = {}
    toplam = 0
    hedefPortAnlik = protokoller[hedefPort]['anlik']
    for siraZaman, Seq, bw in zip(enumerate(hedefPortAnlik['zaman']), hedefPortAnlik['Seq'], hedefPortAnlik['bw']):
        sira, zaman = siraZaman
        if str(int(float(zaman))) not in protokoller[hedefPort]['bw'] :
            protokoller[hedefPort]['bw'][str(int(float(zaman)))] = int(bw)
            protokoller[hedefPort]['aktarilan'][str(int(float(zaman)))] = int(Seq)
            if int(float(onceki['zaman'])) != int(float(zaman)):
                print ( str(int(float(onceki['zaman']))), '   -   ',
                    protokoller[hedefPort]['bw'][str(int(float(zaman)))] / 1024 / 1024 , ' KB / s' )
        else:
            protokoller[hedefPort]['bw'][str(int(float(zaman)))] += int(bw)
            protokoller[hedefPort]['aktarilan'][str(int(float(zaman)))] += int(Seq)
        onceki['zaman'] = zaman
        onceki['Seq'] = Seq
        onceki['bw'] = bw
    byteEkseni = [0]
    byteKatsayi = 0
    bwEkseni = []
    zamanEkseni = []
    for sira in range(int(float(protokoller[hedefPort]['ilk'])), int(float(protokoller[hedefPort]['son']))):
        if str(sira) not in protokoller[hedefPort]['aktarilan']:
            byteEkseni.append(guncelVeri + byteKatsayi)
            bwEkseni.append(0)
            zamanEkseni.append(sira)
            continue
        guncelVeri = round( (protokoller[hedefPort]['aktarilan'][str(sira)] / 1024 / 1024), 5)
        if byteEkseni[-1] > (guncelVeri + byteKatsayi):
            byteKatsayi += byteEkseni[-1]
            print (sira, '   ', byteKatsayi, '   ', byteEkseni[-1], '   ', guncelVeri)
        byteEkseni.append( guncelVeri + byteKatsayi)
        bwEkseni.append( round( ( protokoller[hedefPort]['bw'][str(sira)] / 1024 / 1024), 5) )
        zamanEkseni.append(sira)
    byteEkseni.pop(0)
    return byteEkseni, bwEkseni, zamanEkseni

# ESKİ YAKLAŞIM

def flowGraph_isleme(flowHamVeri): # Wireshark flowGraph TXT export işleme bölümü
    flowVeri = []
    protokoller = {}
    butunIslem = time.time()
    for sira, veri in enumerate(flowHamVeri):
        if len(veri) == 0: continue
        ayrik = veri.split('|')
        zaman = ayrik[1].replace(' ','')
        tekVeri = {}
        if sira % 250000 == 0:
            print (str(sira), ' veri ', str(time.time() - butunIslem), ' ms zamanda işlendi')
        if len(zaman) != 0 and ayrik[3].split(':')[0] == 'TCP':
            tekVeri['zaman'] = zaman
            hususiyetler = re.findall(r'\w+=\d+',ayrik[3])
            portlar = re.findall(r'\d+',ayrik[3])
            tekVeri['kaynak'] = portlar[0]
            tekVeri['hedef'] = portlar[1]
            for hususiyet in hususiyetler:
                tekVeri[hususiyet.split('=')[0]] = hususiyet.split('=')[1]
            if portlar[1] not in protokoller: protokoller[str(portlar[1])] = {'ilk' : zaman, 'anlik': [], 'son': zaman, 'gonderilen': int(tekVeri['Seq']), 'bw': {}}
            else:
                protokoller[str(portlar[1])]['son'] = zaman
                protokoller[str(portlar[1])]['gonderilen'] = int(tekVeri['Seq'])
        if len(tekVeri) != 0: flowVeri += [tekVeri]
    butunIslem = time.time() - butunIslem
    return flowVeri, protokoller, butunIslem

def WS_CSV(flowHam): #Wireshark CSV export tek Yön tek Port işleme bölümü.
    baslik = flowHam.pop(0)
    flowVeri = []
    protokoller = {}
    butunIslem = time.time()
    for sira, veri in enumerate(flowHam):
        if len(veri) == 0: continue
        ayrik = veri.split(',')
        zaman = ayrik[1].replace('"','')
        tekVeri = {}
        if sira % 250000 == 0:
            print (str(sira), ' veri ', str(time.time() - butunIslem), ' ms zamanda işlendi')
        if len(zaman) != 0 and ayrik[4].replace('"','') == 'TCP':
            tekVeri['zaman'] = zaman
            hususiyetler = re.findall(r'\w+=\d+',ayrik[6])
            aciklamalar = re.findall(r'\[.*?\]',ayrik[6])
            portlar = re.findall(r'\d+',ayrik[6])
            for hususiyet in hususiyetler:
                tekVeri[hususiyet.split('=')[0]] = hususiyet.split('=')[1]
            try:
                if portlar[1] not in protokoller:                
                    protokoller[str(portlar[1])] = {'ilk' : zaman, 'anlik': [], 'son': zaman, 'gonderilen': int(tekVeri['Seq']), 'bw': {}}
                else:
                    protokoller[str(portlar[1])]['son'] = zaman
                    protokoller[str(portlar[1])]['gonderilen'] = int(tekVeri['Seq'])
            except Exception as hata:
                print(hata, ' : ', ayrik[0], ' - ', ayrik[1], ' - ', ayrik[6])
        if len(tekVeri) != 0: flowVeri += [tekVeri]
    butunIslem = time.time() - butunIslem
    return flowVeri, protokoller, butunIslem, baslik

def eksenler(csvVeri,protokoller):#Wireshark CSV export tek Yön tek Port işleme bölümü. 
    onceki = {}
    onceki['Seq'] = 0
    onceki['zaman'] = 0
    gonderilen = 0
    hedefPort = 0
    for protokol in protokoller:
        hedefPort = protokol if gonderilen < protokoller[protokol]['gonderilen'] else hedefPort
        if hedefPort in protokoller: gonderilen = protokoller[hedefPort]['gonderilen']
    protokoller[hedefPort]['bw'] = {}
    protokoller[hedefPort]['aktarilan'] = {}
    toplam = 0
    for sira, veri in enumerate(csvVeri):
        if 'Seq' not in veri: continue
        if onceki['Seq'] == veri['Seq']:
            onceki['zaman'] = str(sira)
            continue
        if str(int(float(veri['zaman']))) not in protokoller[hedefPort]['bw'] :
            protokoller[hedefPort]['aktarilan'][str(int(float(veri['zaman'])))] = int(onceki['Seq'])
            protokoller[hedefPort]['bw'][str(int(float(veri['zaman'])))] = int(veri['Seq']) - protokoller[hedefPort]['aktarilan'][str(int(float(veri['zaman'])))]
            if int(float(onceki['zaman'])) != int(float(veri['zaman'])):
                if str(int(float(onceki['zaman']))) not in protokoller[hedefPort]['bw']: continue
                protokoller[hedefPort]['bw'][str(int(float(onceki['zaman'])))] = protokoller[hedefPort]['bw'][str(int(float(onceki['zaman'])))]
                protokoller[hedefPort]['aktarilan'][str(int(float(onceki['zaman'])))] = protokoller[hedefPort]['aktarilan'][str(int(float(onceki['zaman'])))]
                print ( str(int(float(onceki['zaman']))), '   -   ',
                    protokoller[hedefPort]['bw'][str(int(float(onceki['zaman'])))] / 1024 / 1024, ' MB / s' )
        else:
            protokoller[hedefPort]['bw'][str(int(float(veri['zaman'])))] += int(veri['Len'])
            protokoller[hedefPort]['aktarilan'][str(int(float(veri['zaman'])))] += int(veri['Len'])
        onceki = veri
    protokoller[hedefPort]['bw'][str(int(float(onceki['zaman'])))] = protokoller[hedefPort]['bw'][str(int(float(onceki['zaman'])))]
    protokoller[hedefPort]['aktarilan'][str(int(float(onceki['zaman'])))] = protokoller[hedefPort]['aktarilan'][str(int(float(onceki['zaman'])))]
    byteEkseni = [0]
    byteKatsayi = 0
    bwEkseni = []
    zamanEkseni = []
    for sira in range(int(float(protokoller[hedefPort]['ilk'])), int(float(protokoller[hedefPort]['son']))):
        if str(sira) not in protokoller[hedefPort]['aktarilan']:
            byteEkseni.append(guncelVeri + byteKatsayi)
            bwEkseni.append(0)
            zamanEkseni.append(sira)
            continue
        guncelVeri = protokoller[hedefPort]['aktarilan'][str(sira)] / 1024 / 1024
        if byteEkseni[-1] > (guncelVeri + byteKatsayi):
            byteKatsayi += byteEkseni[-1]
            print (sira, '   ', byteKatsayi, '   ', byteEkseni[-1], '   ', guncelVeri)
        byteEkseni.append( guncelVeri + byteKatsayi)
        bwEkseni.append(protokoller[hedefPort]['bw'][str(sira)] / 1024 / 1024)
        zamanEkseni.append(sira)
    byteEkseni.pop(0)
    return byteEkseni, bwEkseni, zamanEkseni


'''
plot = []
plot.append(plt.figure('UzayZamansal', figsize=(len(byteEkseni),len(zamanEkseni))))
plt.plot(zamanEkseni, byteEkseni, 'o', label = 'SMB Protokolü')
plt.xlabel('Zaman')
plt.ylabel('Aktarılan(MB)')
plt.title('Uzay-Zamansal Eğri')
plt.legend()
plt.show()
'''

def legend_without_duplicate_labels(ax):
    handles, labels = ax.get_legend_handles_labels()
    unique = [(h, l) for i, (h, l) in enumerate(zip(handles, labels)) if l not in labels[:i]]
    ax.legend(*zip(*unique))

def yazdir(zaman,byte,bw,renkSayisi):
    zamanNp = np.array(zaman)
    byteNp = np.array(byte)
    bwNp = np.array(bw)
    enYavas = bwNp.min()
    enHizli = bwNp.max()
    renkAdimi = (enHizli-enYavas) / renkSayisi
    renkKatsayi = 750/renkSayisi
    fig, ax = plt.subplots(figsize=(50,50))
    for x,y,renk in zip(zaman, byte, bw):
        etiket = renk
        try:
            alacagiRenk = round ( ( ( renk - enYavas ) / renkAdimi ) * renkKatsayi )
        except Exception as hata:
            print(hata, ' : ', renk, ' ', enYavas, ' ', renkAdimi, ' ', renkKatsayi)
            alacagiRenk = 0
        if alacagiRenk >= 500:  renk = '#AA00'+(hex( alacagiRenk - 500 ).split('x')[1].upper() if len(hex( alacagiRenk - 500 ).split('x')[1].upper()) > 1 else '0' + hex( alacagiRenk - 500 ).split('x')[1].upper())
        elif alacagiRenk >= 250:  renk = '#AA' + ( (hex( alacagiRenk - 250 ).split('x')[1].upper() if len(hex( alacagiRenk - 250 ).split('x')[1].upper()) > 1 else '0' + hex( alacagiRenk - 250 ).split('x')[1].upper()) ) + 'AA'
        elif alacagiRenk < 250:  renk = '#' + ( (hex( alacagiRenk).split('x')[1].upper() if len(hex( alacagiRenk).split('x')[1].upper()) > 1 else '0' + hex( alacagiRenk).split('x')[1].upper()) ) + '0000'
        print(renk)
        ax.plot(x, y, 'o', color=renk, picker=True, label= round(etiket,2) )
    legend_without_duplicate_labels(ax)
    ax.set_title('Uzay-Zamansal Eğri')
    plt.show()

#yazdir(zamanEkseni,byteEkseni,bwEkseni)

'''
fig, ax = plt.subplots()
for x,y,renk in zip(zamanEkseni, byteEkseni, bwEkseni):
    if x< 25 or x > 50: continue
    bw = int ( renk * 10000 )
    if bw < 100000: bw *= 10
    renk = '#' + str(bw)
    ax.plot(x, y, 'o', color=renk, picker=True)

plt.show()
'''

'''

            Anlik = float(protokoller[str(portlar[1])]['son']) - float(protokoller[str(portlar[1])]['anlik'])
            if ( Anlik ) >= 1:
                print ('Port Bilgisi : %s\nBandwidth : %.6f MB/saniye\nZaman Bilgisi : %s' % (str(portlar[1]),( (int(tekVeri['Seq']) - protokoller[str(portlar[1])]['gonderilen']) / Anlik / 8 / 1024 / 1024),zaman))
                protokoller['gonderilen'] = int(tekVeri['Seq'])
                protokoller[str(portlar[1])]['anlik'] = zaman
'''
'''

from pcapAyiklayici import dosyadanOkuyorum, WS_2_CSV, ek2senler,yazdir
flowHamVeri = dosyadanOkuyorum('../Serhan_DB/ApexOneAgent_9167_FTP_ist2bgys.csv')
flowVeri, protokoller, butunIslem, baslik = WS_2_CSV(flowHamVeri)
byteEkseni, bwEkseni, zamanEkseni = ek2senler(flowVeri, protokoller)
yazdir(zamanEkseni,byteEkseni,bwEkseni,60)


#ESKİ YAKLAŞIM
from pcapAyiklayici import dosyadanOkuyorum, WS_CSV, eksenler, yazdir
flowHamVeri = dosyadanOkuyorum('../Serhan_DB/ApexOneAgent_9167_445_ist2bgys.csv')
flowVeri, protokoller, butunIslem, baslik = WS_CSV(flowHamVeri)
byteEkseni, bwEkseni, zamanEkseni = eksenler(flowVeri, protokoller)
yazdir(zamanEkseni,byteEkseni,bwEkseni,60)

'''

