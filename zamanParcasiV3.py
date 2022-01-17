import re,time,os
import matplotlib.pyplot as plt, matplotlib.dates as md, numpy as np, pandas as pd, datetime as dt
import threading, queue, time, pickle

kuyruk = queue.Queue()

def ikinciyiAl(eleman):
    return eleman[1]

def Resim_isle2(islem_zamani,uzay_ekseni,aktarilan_bit,dosyaAdi, kaynak, hedef, islenenAkis,sirasi):
    global ax
    sc = ax.scatter(islem_zamani,uzay_ekseni,c=aktarilan_bit, marker='o', cmap='jet_r', vmin=0, vmax=60)
    plt.axis('off')
    plt.yticks([])
    plt.xticks([])
    plt.subplots_adjust(left=0, right=1, top=1, bottom=0)

def Resim_isle(islem_zamani,uzay_ekseni,aktarilan_bit,dosyaAdi, kaynak, hedef, islenenAkis,sirasi):
    global ax
    sc = ax.scatter(islem_zamani,uzay_ekseni,c=aktarilan_bit, marker='o', cmap='jet_r', vmin=0, vmax=60)
    plt.subplots_adjust(bottom=0.2)
    plt.xticks( rotation=25 )
    legend_without_duplicate_labels(ax)
    ax.set_title('Uzay-Zamansal Eğri '+str(dosyaAdi)+'_'+str(islenenAkis)+'_'+str(kaynak)+'_'+str(hedef))

def legend_without_duplicate_labels(ax):
    handles, labels = ax.get_legend_handles_labels()
    unique = [(h, l) for i, (h, l) in enumerate(zip(handles, labels)) if l not in labels[:i]]
    ax.legend(*zip(*unique))

def saldiri_verisi_isle(dosyaAdlari,saldiriVerisi, hata_noktasi=0, aralik='2018 15:4', baslangic='Mar 2, 2018 15:46', bitis='Mar 2, 2018 15:59', zaman_carpani=1):
    baslangic = dt.datetime.strptime(baslangic+':00.000000000 +03','%b %d, %Y %H:%M:%S.%f000 %Z')
    bitis = dt.datetime.strptime(bitis+':59.999999000 +03','%b %d, %Y %H:%M:%S.%f000 %Z')
    zaman_ekseni = np.arange(0,(bitis - baslangic).total_seconds() * zaman_carpani)
    mode = 0o777
    zaman_kaydirici = 0
    isParcalari = []
    veriAkislar = []
    toplamSure = time.time()
    for veri in saldiriVerisi:
        print(veri, '   işleniyor')
        akislar = []
        for akis in saldiriVerisi[veri].groupby('tcp.stream'):
            if len(akis[1]) > 50:
                akislar.append([akis[0],len(akis[1])])
        akislar.sort(key=ikinciyiAl, reverse=True) # satır 16
    #    dosyaAdlari.pop(dosyaAdlari.index('.csv'))
    #    if os.path.isdir('resimler/'+dosyaAdlari[veri].replace('.csv','')) is False:
    #        os.mkdir('resimler/'+dosyaAdlari[veri].replace('.csv',''), mode = mode, dir_fd = None)
        for akis in akislar:
            print(veri, '   ',akis[0],' akışı işleniyor')
            basla = time.time()
            trafik = {'alinan': [], 'gonderilen': [], 'akisim': {'uzay_ekseni':{}, 'aktarilan_bit':{}, 'islem_zamani':{}}}
            trafik['alinan'] = saldiriVerisi[veri].loc[ ( saldiriVerisi[veri]['tcp.stream'] == int(akis[0]) ) & ( saldiriVerisi[veri]['tcp.seq'] < saldiriVerisi[veri]['tcp.ack'] )]
            trafik['gonderilen'] = saldiriVerisi[veri].loc[ ( saldiriVerisi[veri]['tcp.stream'] == int(akis[0]) ) & ( saldiriVerisi[veri]['tcp.seq'] > saldiriVerisi[veri]['tcp.ack'] )]
            if len(trafik['gonderilen'].loc[trafik['gonderilen']['frame.time'].str.contains(aralik) == True]) == 0: continue
            ilk = int((dt.datetime.strptime(trafik['gonderilen'].loc[trafik['gonderilen']['frame.time'].str.contains(aralik) == True].head(1)['frame.time'].values[0],'%b %d, %Y %H:%M:%S.%f000 %Z') - baslangic).total_seconds() * zaman_carpani)
            son = int((dt.datetime.strptime(trafik['gonderilen'].loc[trafik['gonderilen']['frame.time'].str.contains(aralik) == True].tail(1)['frame.time'].values[0],'%b %d, %Y %H:%M:%S.%f000 %Z') - baslangic).total_seconds() * zaman_carpani)
            islemZamani = dt.datetime.strptime(trafik['gonderilen'].head(1)['frame.time'].values[0],'%b %d, %Y %H:%M:%S.%f000 %Z')
            SonislemZamani = dt.datetime.strptime(trafik['gonderilen'].tail(1)['frame.time'].values[0],'%b %d, %Y %H:%M:%S.%f000 %Z')
            if islemZamani > bitis: continue
            elif SonislemZamani < baslangic: continue
            elif islemZamani < baslangic:
                islemZamani = baslangic
                zaman_oteleyici = ilk
            elif SonislemZamani > bitis:
                SonislemZamani = bitis
            for zaman in zaman_ekseni:
                trafik['akisim']['aktarilan_bit'][zaman] = 0
            for kayit in trafik['gonderilen'].index: #37
                kayit_zamani = dt.datetime.strptime(saldiriVerisi[veri].loc()[kayit]['frame.time'],'%b %d, %Y %H:%M:%S.%f000 %Z')
                baslangictan_bu_yana = kayit_zamani - baslangic
                if saldiriVerisi[veri].loc()[kayit]['tcp.seq'] == 'nan' or saldiriVerisi[veri].loc()[kayit]['tcp.len'] == 'nan' or dt.datetime.strptime(saldiriVerisi[veri].loc()[kayit]['frame.time'],'%b %d, %Y %H:%M:%S.%f000 %Z') < baslangic or dt.datetime.strptime(saldiriVerisi[veri].loc()[kayit]['frame.time'],'%b %d, %Y %H:%M:%S.%f000 %Z') > bitis: continue
                try:
                    trafik['akisim']['uzay_ekseni'][int(baslangictan_bu_yana.total_seconds()*zaman_carpani)] = trafik['gonderilen'].loc()[kayit]['tcp.seq']
                    trafik['akisim']['aktarilan_bit'][int(baslangictan_bu_yana.total_seconds()*zaman_carpani)] += trafik['gonderilen'].loc()[kayit]['tcp.len'] 
                except Exception as hata: # satır 44
                    print(dosyaAdlari[veri],'  -  ',veri, '   -   ', kayit,'   -   ', hata)
#        tumakislar.append([dosyaAdlari[veri], veri, akislar])
            if len(trafik['akisim']['uzay_ekseni']) < 50: continue
            kalinan_yer = trafik['akisim']['uzay_ekseni'][ilk]
            for zaman in zaman_ekseni:
                if int(zaman) not in trafik['akisim']['uzay_ekseni']: trafik['akisim']['uzay_ekseni'][int(zaman)] = kalinan_yer #37
                else: kalinan_yer = trafik['akisim']['uzay_ekseni'][zaman]
            uzay_ekseni = []
            aktarilan_bit = []
            islem_zamani = []
            for zaman in zaman_ekseni: # satır 53
    #            if trafik['akisim']['uzay_ekseni'][zaman] > 999999: continue
                uzay_ekseni.append(trafik['akisim']['uzay_ekseni'][zaman])
                aktarilan_bit.append(trafik['akisim']['aktarilan_bit'][zaman])
                islem_zamani.append(islemZamani + dt.timedelta(milliseconds=int(zaman)))
            if uzay_ekseni[-1] < 50000: continue
            print(veri,' - ', dosyaAdlari[veri],'   -   ',len(islem_zamani),'   -   ',len(uzay_ekseni),'   -   ', (time.time() - basla))
            veriAkislar.append([islem_zamani,uzay_ekseni,aktarilan_bit,dosyaAdlari[veri],str(trafik['gonderilen'].tail(1)['tcp.srcport'].values[0]),str(trafik['gonderilen'].tail(1)['tcp.dstport'].values[0]),str(akis[0])])
    return veriAkislar

def saldiriGunleriOku(anadizin,gun,saldirilanlar):
    basla = time.time()
    flowHamVeriler = []
    dosyaAdlari = []
    for sira,saldirilan in enumerate(saldirilanlar):
        saldirilanlar[sira] = '172.31.69.'+str(saldirilan)
    for dosya in os.listdir(anadizin+gun):
        if 'var' not in ['var' if saldirilan in dosya else 'yok' for saldirilan in saldirilanlar]: continue
        ekle = 1
        try:
            flowHamVeri = pd.read_csv(anadizin+gun+dosya)
        except Exception as hata:
            ekle = 0
            print(anadizin,gun,dosya,' dosyasını işlerken hata oluştu   : ', hata)
        if ekle:
            dosyaAdlari.append([gun,dosya])
            flowHamVeriler.append(flowHamVeri)
    print('Toplam geçen süre : ',time.time() - basla)
    return dosyaAdlari,flowHamVeriler

def normalGunleriOku(anadizin,gun,okunacaklar):
    basla = time.time()
    flowHamVeriler = []
    dosyaAdlari = []
    for sira,okunacak in enumerate(okunacaklar):
        okunacaklar[sira] = '172.31.65.'+str(okunacak)
    for dosya in os.listdir(anadizin+gun):
        if 'var' not in ['var' if okunacak in dosya else 'yok' for okunacak in okunacaklar]: continue
        ekle = 1
        try:
            flowHamVeri = pd.read_csv(anadizin+gun+dosya)
        except Exception as hata:
            ekle = 0
            print(anadizin,gun,dosya,' dosyasını işlerken hata oluştu   : ', hata)
        if ekle:
            dosyaAdlari.append([gun,dosya])
            flowHamVeriler.append(flowHamVeri)
    print('Toplam geçen süre : ',time.time() - basla)
    return dosyaAdlari,flowHamVeriler

def trafikAyir(akislar,saatler):
    basla = time.time()
    trafik = {}
    for flow in range(len(akislar)):
        trafik[flow] = akislar[flow].loc[ ( akislar[flow]['frame.time'].str.contains(saatler[0]) == True ) | ( akislar[flow]['frame.time'].str.contains(saatler[1]) == True )]
    #    veriler[flow] = flowHamVeriler[flow]
        print(flow,' pc trafigi, geçen süre : ', time.time() - basla)
    print('Toplam geçen süre : ',time.time() - basla)
    return trafik

# FAZ 1: Dosyadan okuma 

anadizin = '../Serhan_DB/IDS2018/'
gunler = ['Persembe-15-02-2018/','Cuma-16-02-2018/','Cuma-23-02-2018/','Persembe-01-03-2018/','Cuma-02-03-2018/']

dosyaAdlari = {}

dosyaAdlari['2Mart'], flow2MartVeriler = saldiriGunleriOku(anadizin,gunler[4],[6,8,10,12,14,17,23,26,29,30])
dosyaAdlari['1Mart'], flow1MartVeriler = saldiriGunleriOku(anadizin,gunler[3],[6,8,10,12,14,17,23,26,29,30])
dosyaAdlari['23Subat'], flow23SubatVeriler = saldiriGunleriOku(anadizin,gunler[2],[28])
dosyaAdlari['16Subat'], flow16SubatVeriler = saldiriGunleriOku(anadizin,gunler[1],[25])
dosyaAdlari['15Subat'], flow15SubatVeriler = saldiriGunleriOku(anadizin,gunler[0],[25])
dosyaAdlari['15SubatNormal'], flow15SubatNormal = normalGunleriOku(anadizin,gunler[0],[10,113,123,124,126,14,28,29,34,40,50,56,66,76,81,86,88,107,109,112,118,119,121,122,18,27,30,32,33,36,37,39,41,43,44,45,59,5,64,65,71,72,75,82,84,85,8,91,93,96,98,100,117,13,16,20,25,49,61,67,68,6,77,79,80,83,103,104,105,108,114,115,116,11,125,17,19,21,23,24,35,38,42,46,47,48,51,52,55,57,58,69,70,73,78,87,89,90,99,9])

# Saldırı verileri lookup-table

#2 Mart 2018 -> 10:11 - 11:34 --- 172.31.69.-6,8,10,12,14,17,23,26,29,30 bot
#2 Mart 2018 -> 14:24 - 15:55 --- 172.31.69.-6,8,10,12,14,17,23,26,29,30 bot
#1 Mart 2018 -> 09:57 - 10:55 --- 172.31.69.13 infiltrate
#1 Mart 2018 -> 14:00 - 15:37 --- 172.31.69.13 infiltrate
#23 Şubat 2018 -> 10:03 - 11:03 --- 172.31.69.28 WEB
#23 Şubat 2018 -> 13:00 - 14:10 --- 172.31.69.28 XSS
#16 Şubat 2018 -> 10:12 - 11:08 --- 172.31.69.25 DoS-SlowHTTPTest
#16 Şubat 2018 -> 13:45 - 14:19 --- 172.31.69.25 DoS-Hulk
#15 Şubat 2018 -> 10:59 - 11:40 --- 172.31.69.25 DoS-Slowloris
#15 Şubat 2018 -> 09:26 - 10:09 --- 172.31.69.25 DoS-GoldenEye

# FAZ 2: Okunan verileri daha küçük ve resme işlenebilir şekilde anlamlandır 

saldiriBot = [trafikAyir(flow2MartVeriler,['2018 17:','2018 18:']),trafikAyir(flow2MartVeriler,['2018 21:','2018 22:'])] # 2 Mart 2018
saldiriInfiltration = trafikAyir(flow1MartVeriler,['2018 16:','2018 17:']),trafikAyir(flow1MartVeriler,['2018 21:','2018 22:']) # 1 Mart 2018
saldiri_BFXSS_BFWeb = trafikAyir(flow23SubatVeriler,['2018 17:','2018 18:']),trafikAyir(flow23SubatVeriler,['2018 20:','2018 21:']) # 23 Şubat 2018
saldiri_DoS_SlowHTTP_Hulk = trafikAyir(flow16SubatVeriler,['2018 17:','2018 18:']),trafikAyir(flow16SubatVeriler,['2018 19:','2018 20:']) # 16 Şubat 2018
saldiri_DoS_GE_SL = trafikAyir(flow15SubatVeriler,['2018 16:','2018 17:']),trafikAyir(flow15SubatVeriler,['2018 18:','2018 19:']) # 15 Şubat 2018
normalVeriler = trafikAyir(flow15SubatNormal, ['2018 16:','2018 18:']) # Normal Veriler, hepsinden toplanabilir.

# FAZ 3: İhtiyaç olan verileri daha küçük ve resme sığabilecek olanlar arasından seç

veriAkislar16 = saldiri_verisi_isle(saldiri_DoS_SlowHTTP_Hulk[0], hata_noktasi=0, aralik='2018 17:1', baslangic='Feb 16, 2018 17:12', bitis='Feb 16, 2018 18:08', zaman_carpani=1)
veriAkislar15p1 = saldiri_verisi_isle(saldiri_DoS_GE_SL[0], hata_noktasi=0, aralik='2018 16:3', baslangic='Feb 15, 2018 16:26', bitis='Feb 15, 2018 17:09', zaman_carpani=1)
veriAkislar15p2 = saldiri_verisi_isle(saldiri_DoS_GE_SL[1], hata_noktasi=0, aralik='2018 18:2', baslangic='Feb 15, 2018 17:59', bitis='Feb 15, 2018 18:40', zaman_carpani=1)
veriAkislar15normal = saldiri_verisi_isle(dosyaAdlari['15SubatNormal'], normalVeriler, hata_noktasi=0, aralik='2018 18:2', baslangic='Feb 15, 2018 16:20', bitis='Feb 15, 2018 18:45', zaman_carpani=1)
veriAkislar23normal = saldiri_verisi_isle(dosyaAdlari, veriler, hata_noktasi=0, aralik='2018 22:', baslangic='Feb 23, 2018 22:00', bitis='Feb 23, 2018 22:59', zaman_carpani=1)

# FAZ 4 ve FAZ 5 için kullanıldı.

bitisler = []
for veriAkis in veriAkislar23normal:
    for sure in veriAkis[0]:
        if sure.replace(microsecond=0) not in bitisler:
            bitisler.append(sure.replace(microsecond=0))

# FAZ 4 (Tercihli): Bilgisayar adlarına göre resimlere dök

bilgAdlari = []
for veriAkis in veriAkislar23normal:
    if veriAkis[3].split('.')[0]+'-'+str(veriAkis[3].split('.')[2]) not in bilgAdlari:
        bilgAdlari.append(veriAkis[3].split('.')[0]+'-'+str(veriAkis[3].split('.')[2]))

for bitis in bitisler:
    for bilg in bilgAdlari:
        veriVar = 0
        fig, ax = plt.subplots(figsize=(6,8))
        for sirasi,veriAkis in enumerate(veriAkislar23normal):
            if veriAkis[3].split('.')[0]+'-'+str(veriAkis[3].split('.')[2]) == bilg:
                zaman, uzay, renk = [],[],[]
                for sira, sure in enumerate(veriAkis[0]):
                    if bitis == sure.replace(microsecond=0):
                        zaman.append(veriAkis[0][sira])
                        uzay.append(veriAkis[1][sira])
                        renk.append(veriAkis[2][sira])
                if len(zaman) == 0: continue
                veriVar = 1
                Resim_isle2(zaman, uzay, renk, veriAkis[3], veriAkis[4], veriAkis[5], veriAkis[6], sirasi)
    #    plt.ylim([96000,995000])
        if veriVar == 1:
            fig.savefig('Proje_Eski_Ciktilar/resimler21/Uzay-Zamansal_Akislar_pcBazli_23Şubat22-23_'+bilg+'_'+str(bitis.hour)+'-'+str(bitis.minute)+'-'+str(bitis.second)+'.png')
        plt.close(fig)

# FAZ 5 (Tercihli): Bütün akışları resimlere dök
for bitis in bitisler:
    dosyasi = []
    fig, ax = plt.subplots(figsize=(6,8))
    resim = 0
    basla = time.time()
    for sirasi,veriAkis in enumerate(veriAkislar23normal):
        zaman, uzay, renk = [],[],[]
        for sira, sure in enumerate(veriAkis[0]):
            if bitis == sure.replace(microsecond=0):
                zaman.append(veriAkis[0][sira])
                uzay.append(veriAkis[1][sira])
                renk.append(veriAkis[2][sira])
            if len(zaman) == 0: continue
        Resim_isle2(zaman,uzay,renk, veriAkis[3], veriAkis[4], veriAkis[5], veriAkis[6], sirasi)
        dosyasi.append([veriAkis[3], veriAkis[4], veriAkis[5], veriAkis[6]])
    fig.savefig('Proje_Eski_Ciktilar/resimler20/Uzay-Zamansal_Akislar_Hepsi_'+veriAkis[3]+'_'+str(bitis.hour)+'-'+str(bitis.minute)+'-'+str(bitis.second)+'.png')
    plt.close(fig)
    with open('Proje_Eski_Ciktilar/resimler20/Uzay-Zamansal_Akislar_Hepsi_'+veriAkis[3]+'_'+str(bitis.hour)+'-'+str(bitis.minute)+'-'+str(bitis.second)+'.kunye', 'w+') as kunye:
        kunye.write('\n'.join(['\t'.join([deg for deg in deger]) for deger in dosyasi]))
    print(sirasi,' - ',veriAkis[3],' işleniyor. ', time.time()-basla, ' sürede işlendi.')

# FAZ 6 Modelin Oluşturulması








