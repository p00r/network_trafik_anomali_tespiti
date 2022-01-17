import re,time,os
import matplotlib.pyplot as plt, numpy as np, pandas as pd

#IDS 2018 verisi tshark çıktı metni üzerinden yapılan ayrım
#dakika10 = flowHamVeri.loc[flowHamVeri['frame.time'].str.contains(' 22:4')]


#IDS 2018 - inceleme çalışması
# Pcap - tshark ayrıştırma:
# tshark -r /media/msercin/FE607C5E607C1F97/MakineÖğrenmesiProjeleri/IDS2018/Cuma-16-02-2018/pcap/capDESKTOP-AN3U28N-172.31.64.17 -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e tcp.stream -e tcp.seq -e tcp.len -e tcp.nxtseq -e tcp.ack -e tcp.time_relative -e tcp.time_delta -E header=y -E separator=, -E quote=d -E occurrence=f > capDESKTOP-AN3U28N-172.31.64.17.csv
#find /media/msercin/FE607C5E607C1F97/MakineÖğrenmesiProjeleri/IDS2018/Cuma-16-02-2018/pcap/ -name "*" -exec tshark -r {} -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e tcp.stream -e tcp.seq -e tcp.len -e tcp.nxtseq -e tcp.ack -e tcp.time_relative -e tcp.time_delta -E header=y -E separator=, -E quote=d -E occurrence=f -w {}.csv
#for dosyasi in /media/msercin/FE607C5E607C1F97/MakineÖğrenmesiProjeleri/IDS2018/Cuma-16-02-2018/pcap/*; do dizin=($(echo $dosyasi | tr '/' "\n")); tshark -r "${dosyasi}" -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e tcp.stream -e tcp.seq -e tcp.len -e tcp.nxtseq -e tcp.ack -e tcp.time_relative -e tcp.time_delta -E header=y -E separator=, -E quote=d -E occurrence=f > "${dizin[7]}.csv"; done

anadizin = '../Serhan_DB/IDS2018/'
gun = 'Cuma-16-02-2018/'

#dosya = 'capDESKTOP-AN3U28N-172.31.64.17.csv'
#flowHamVeri = pd.read_csv(anadizin+gun+dosya)

#flowHamVeri.loc[flowHamVeri['tcp.dstport'] == 21]
#flowHamVeri.loc[flowHamVeri['tcp.dstport'] == 22]
#flowHamVeri.loc[flowHamVeri['tcp.dstport'] == 25]
#flowHamVeri.loc[flowHamVeri['tcp.dstport'] == 80]
#flowHamVeri.loc[flowHamVeri['tcp.dstport'] == 139]
#flowHamVeri.loc[flowHamVeri['tcp.dstport'] == 443]
#flowHamVeri.loc[flowHamVeri['tcp.dstport'] == 445]
#flowHamVeri.loc[flowHamVeri['tcp.dstport'] == 3389]

# Tek Dosya İçin
hedefPortlar = np.array(flowHamVeri['tcp.dstport'].unique())
akanVeriler = np.array(flowHamVeri['tcp.stream'].unique())

portlar = {}
rastlanmaP = []
akim = {}
rastlanmaA = []

for hedefPort in hedefPortlar:
    portlar[len(flowHamVeri.loc[flowHamVeri['tcp.dstport'] == hedefPort])] = hedefPort
    rastlanmaP.append(len(flowHamVeri.loc[flowHamVeri['tcp.dstport'] == hedefPort]))

for akanVeri in akanVeriler:
    akim[len(flowHamVeri.loc[flowHamVeri['tcp.stream'] == akanVeri])] = akanVeri
    rastlanmaA.append(len(flowHamVeri.loc[flowHamVeri['tcp.stream'] == akanVeri]))

rastlanmaP = np.array(rastlanmaP).astype(int)
rastlanmaA = np.array(rastlanmaA).astype(int)

rastlanmaP.sort()
rastlanmaA.sort()

rastlanmaSirali = np.flip(rastlanmaA)
akanVeriler = []

for rastlanma in rastlanmaSirali[:21]:
    protokoller = flowHamVeri.loc[ flowHamVeri['tcp.stream'] == akim[rastlanma] ]['tcp.dstport'].unique()
    protokoller.sort()
    akanVeriler.append([akim[rastlanma],protokoller[0],flowHamVeri.loc[ ( flowHamVeri['tcp.stream'] == akim[rastlanma] ) & ( flowHamVeri['tcp.dstport'] == protokoller[0])]])

#https_trafigi = flowHamVeri.loc[ ( flowHamVeri['tcp.stream'] == akim[rastlanmaA[-1]] ) & ( flowHamVeri['tcp.dstport'] == 443 ) ]

for akanVeri in akanVeriler:
    siralar = akanVeri[2][['tcp.seq','tcp.time_relative']].index
    ilk = akanVeri[2][['tcp.seq','tcp.time_relative']].loc()[siralar[0]]['tcp.time_relative'].astype(int)
    son = akanVeri[2][['tcp.seq','tcp.time_relative']].loc()[siralar[-1]]['tcp.time_relative'].astype(int)
    zaman_ekseni = np.arange(son - ilk + 1)
    uzay_eksenSoz = {}
    aktarilan_bitSoz = {}
    for zaman in zaman_ekseni:
        aktarilan_bitSoz[zaman] = 0
    for sira in siralar:
        uzay_eksenSoz[akanVeri[2].loc()[sira]['tcp.time_relative'].astype(int)] = akanVeri[2].loc()[sira]['tcp.seq']
        aktarilan_bitSoz[akanVeri[2].loc()[sira]['tcp.time_relative'].astype(int)] += akanVeri[2].loc()[sira]['tcp.len']
    kalinan_yer = uzay_eksenSoz[ilk]
    for zaman in zaman_ekseni:
        if zaman not in uzay_eksenSoz:
            uzay_eksenSoz[zaman] = kalinan_yer
        else: kalinan_yer = uzay_eksenSoz[zaman]
    uzay_ekseni = []
    aktarilan_bit = []
    for zaman in zaman_ekseni:
        uzay_ekseni.append(uzay_eksenSoz[zaman])
        aktarilan_bit.append(aktarilan_bitSoz[zaman])
    resim = plt.figure('UzayZamansal', figsize=(32,24))
    plt.scatter(zaman_ekseni,uzay_ekseni,c=aktarilan_bit, cmap='jet_r', vmin=0, vmax=6000)
    plt.xlabel('Zaman')
    plt.ylabel('Bandwidth(Bit/s)')
    plt.title('Uzay-Zamansal Eğri - Akış : ' + str(akanVeri[0]) + ', Protokol : ' + str(akanVeri[1]))
    plt.legend()
    resim.savefig('Uzay-Zamansal_Akis_' + str(akanVeri[0]) + '_port_' + str(akanVeri[1])+'.png')
    plt.close(resim)

#Çok Dosya Tek gün için

basla = time.time()

flowHamVeriler = []
for dosya in os.listdir(anadizin+gun):
    ekle = 1
    try:
        flowHamVeri = pd.read_csv(anadizin+gun+dosya)
    except Exception as hata:
        ekle = 0
        print(anadizin,gun,dosya,'   : ', hata)
    if ekle: flowHamVeriler.append(flowHamVeri)

print('Toplam geçen süre : ,'time.time() - basla)



with open('../Serhan_DB/FlowGraph-CentosTransfer_445_Mse2Yagmur.txt') as flowDosya:
    flowHam = flowDosya.read()

dosyaOkurken = time.time() - dosyadanOkuma

print ('Dosyayı okurken geçen süre : ', str(dosyaOkurken))

flowHamVeri = flowHam.split('\n')
cikartilanlar = ()

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

onceki = {}
onceki['Seq'] = 0
onceki['zaman'] = 0
protokoller['445']['bw'] = {}
protokoller['445']['aktarilan'] = {}
toplam = 0

for sira, veri in enumerate(flowVeri):
    if onceki['Seq'] == veri['Seq']: continue
    if str(int(float(veri['zaman']))) not in protokoller['445']['bw'] :
        protokoller['445']['aktarilan'][str(int(float(veri['zaman'])))] = int(onceki['Seq'])
        protokoller['445']['bw'][str(int(float(veri['zaman'])))] = int(veri['Seq']) - protokoller['445']['aktarilan'][str(int(float(veri['zaman'])))]
        if int(float(onceki['zaman'])) != int(float(veri['zaman'])):
            protokoller['445']['bw'][str(int(float(onceki['zaman'])))] = protokoller['445']['bw'][str(int(float(onceki['zaman'])))]
            protokoller['445']['aktarilan'][str(int(float(onceki['zaman'])))] = protokoller['445']['aktarilan'][str(int(float(onceki['zaman'])))]
            print ( str(int(float(onceki['zaman']))), '   -   ',
                protokoller['445']['bw'][str(int(float(onceki['zaman'])))] / 1024 / 1024, ' MB / s' )
    else:
        protokoller['445']['bw'][str(int(float(veri['zaman'])))] += int(veri['Len'])
        protokoller['445']['aktarilan'][str(int(float(veri['zaman'])))] += int(veri['Len'])
    onceki = veri

protokoller['445']['bw'][str(int(float(onceki['zaman'])))] = protokoller['445']['bw'][str(int(float(onceki['zaman'])))]
protokoller['445']['aktarilan'][str(int(float(onceki['zaman'])))] = protokoller['445']['aktarilan'][str(int(float(onceki['zaman'])))]

byteEkseni = []
bwEkseni = []
zamanEkseni = []
for sira in range(int(float(protokoller['445']['ilk'])), int(float(protokoller['445']['son']))):
    byteEkseni.append(protokoller['445']['aktarilan'][str(sira)] / 1024 / 1024)
    bwEkseni.append(protokoller['445']['bw'][str(sira)] / 1024 / 1024)
    zamanEkseni.append(sira)

plot = []
plot.append(plt.figure('UzayZamansal', figsize=(len(bwEkseni),len(zamanEkseni))))
plt.plot(zamanEkseni, bwEkseni, label = 'SMB Protokolü')
plt.xlabel('Zaman')
plt.ylabel('Bandwidth(M/B)')
plt.title('Uzay-Zamansal Eğri')
plt.legend()
plt.show()



'''

            Anlik = float(protokoller[str(portlar[1])]['son']) - float(protokoller[str(portlar[1])]['anlik'])
            if ( Anlik ) >= 1:
                print ('Port Bilgisi : %s\nBandwidth : %.6f MB/saniye\nZaman Bilgisi : %s' % (str(portlar[1]),( (int(tekVeri['Seq']) - protokoller[str(portlar[1])]['gonderilen']) / Anlik / 8 / 1024 / 1024),zaman))
                protokoller['gonderilen'] = int(tekVeri['Seq'])
                protokoller[str(portlar[1])]['anlik'] = zaman
'''
