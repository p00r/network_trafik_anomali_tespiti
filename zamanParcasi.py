import re,time,os
import matplotlib.pyplot as plt, matplotlib.dates as md, numpy as np, pandas as pd, datetime as dt
import threading, queue, time

kuyruk = queue.Queue()

anadizin = '../Serhan_DB/IDS2018/'
gun = 'Persembe-15-02-2018/'
gun = 'Cuma-16-02-2018/'
gun = 'Cuma-23-02-2018/'
gun = 'Persembe-01-03-2018/'
gun = 'Cuma-02-03-2018/'

def ikinciyiAl(eleman):
    return eleman[1]

basla = time.time()

flowHamVeriler = []
dosyaAdlari = []
for dosya in os.listdir(anadizin+gun):
    ekle = 1
    try:
        flowHamVeri = pd.read_csv(anadizin+gun+dosya)
    except Exception as hata:
        ekle = 0
        print(anadizin,gun,dosya,'   : ', hata)
    if ekle:
        dosyaAdlari.append(dosya)
        flowHamVeriler.append(flowHamVeri)

print('Toplam geçen süre : ',time.time() - basla) # Toplam geçen süre :  315.61214089393616

basla = time.time()
saldiriBot = {} # 2 Mart 2018

for flow in range(len(flowHamVeriler)):
    saldiriBot[flow] = flowHamVeriler[flow].loc[ ( flowHamVeriler[flow]['frame.time'].str.contains('2018 10') == True ) | ( flowHamVeriler[flow]['frame.time'].str.contains('2018 11:') == True ) | ( flowHamVeriler[flow]['frame.time'].str.contains('2018 14:') == True ) | ( flowHamVeriler[flow]['frame.time'].str.contains('2018 15:') == True )]
#    veriler[flow] = flowHamVeriler[flow]
    print(flow,' pc trafigi, geçen süre : ', time.time() - basla)

print('Toplam geçen süre : ',time.time() - basla) 

basla = time.time()
saldiriInfiltration = {} # 1 Mart 2018
for flow in range(len(flowHamVeriler)):
    saldiriInfiltration[flow] = flowHamVeriler[flow].loc[ ( flowHamVeriler[flow]['frame.time'].str.contains('2018 09:') == True ) | ( flowHamVeriler[flow]['frame.time'].str.contains('2018 10:') == True ) | ( flowHamVeriler[flow]['frame.time'].str.contains('2018 14:') == True ) | ( flowHamVeriler[flow]['frame.time'].str.contains('2018 15:') == True )]
#    veriler[flow] = flowHamVeriler[flow]
    print(flow,' pc trafigi, geçen süre : ', time.time() - basla)

print('Toplam geçen süre : ',time.time() - basla) 


basla = time.time()
saldiri_BFXSS_BFWeb = {} # 23 Şubat 2018
for flow in range(len(flowHamVeriler)):
    saldiri_BFXSS_BFWeb[flow] = flowHamVeriler[flow].loc[ ( flowHamVeriler[flow]['frame.time'].str.contains('2018 10') == True ) | ( flowHamVeriler[flow]['frame.time'].str.contains('2018 13:') == True ) | ( flowHamVeriler[flow]['frame.time'].str.contains('2018 15:') == True )]
#    veriler[flow] = flowHamVeriler[flow]
    print(flow,' pc trafigi, geçen süre : ', time.time() - basla)

print('Toplam geçen süre : ',time.time() - basla)


basla = time.time()
saldiri_DoS_SlowHTTP_Hulk = {} # 16 Şubat 2018
for flow in range(len(flowHamVeriler)):
    saldiri_BFXSS_BFWeb[flow] = flowHamVeriler[flow].loc[ ( flowHamVeriler[flow]['frame.time'].str.contains('2018 10') == True ) | ( flowHamVeriler[flow]['frame.time'].str.contains('2018 13:') == True )]
#    veriler[flow] = flowHamVeriler[flow]
    print(flow,' pc trafigi, geçen süre : ', time.time() - basla)

print('Toplam geçen süre : ',time.time() - basla)


basla = time.time()
saldiri_DoS_GE_SL = {} # 15 Şubat 2018
for flow in range(len(flowHamVeriler)):
    saldiri_DoS_GE_SL[flow] = flowHamVeriler[flow].loc[ ( flowHamVeriler[flow]['frame.time'].str.contains('2018 09') == True ) | ( flowHamVeriler[flow]['frame.time'].str.contains('2018 11:') == True )]
#    veriler[flow] = flowHamVeriler[flow]
    print(flow,' pc trafigi, geçen süre : ', time.time() - basla)

print('Toplam geçen süre : ',time.time() - basla)

basla = time.time()
veriler = {}

for flow in range(len(flowHamVeriler)):
    veriler[flow] = flowHamVeriler[flow].loc[ ( flowHamVeriler[flow]['frame.time'].str.contains('2018 22') == True ) | ( flowHamVeriler[flow]['frame.time'].str.contains('2018 00:') == True ) ]
#    veriler[flow] = flowHamVeriler[flow]
    print(flow,' pc trafigi, geçen süre : ', time.time() - basla)

print('Toplam geçen süre : ',time.time() - basla) 

# Bütün zaman serilerini dinamik oluştur.
mode = 0o777
zaman_carpani = 1000
tumakislar = []
for veri in veriler:
    akislar = []
    for akis in veriler[veri].groupby('tcp.stream'):
        if len(akis[1]) > 50:
            akislar.append([akis[0],len(akis[1])])
    akislar.sort(key=ikinciyiAl, reverse=True)
#    dosyaAdlari.pop(dosyaAdlari.index('.csv'))
    if os.path.isdir('resimler/'+dosyaAdlari[veri].replace('.csv','')) is False:
        os.mkdir('resimler/'+dosyaAdlari[veri].replace('.csv',''), mode = mode, dir_fd = None)
    for akis in akislar:
        trafik = {'alinan': [], 'gonderilen': [], 'akisim': {'uzay_ekseni':{}, 'aktarilan_bit':{}, 'islem_zamani':{}}}
        trafik['alinan'] = veriler[veri].loc[ ( veriler[veri]['tcp.stream'] == int(akis[0]) ) & ( veriler[veri]['tcp.seq'] < veriler[veri]['tcp.ack'] )]
        trafik['gonderilen'] = veriler[veri].loc[ ( veriler[veri]['tcp.stream'] == int(akis[0]) ) & ( veriler[veri]['tcp.seq'] > veriler[veri]['tcp.ack'] )]
        ilk = (trafik['gonderilen'].head(1)['tcp.time_relative'].values[0] * zaman_carpani).astype(int)
        son = (trafik['gonderilen'].tail(1)['tcp.time_relative'].values[0] * zaman_carpani).astype(int)
        islemZamani = dt.datetime.strptime(trafik['gonderilen'].head(1)['frame.time'].values[0],'%b %d, %Y %H:%M:%S.%f000 %Z')
        zaman_ekseni = np.arange(ilk,son+1)
        if len(zaman_ekseni) < 50: continue
        for zaman in zaman_ekseni:
            trafik['akisim']['aktarilan_bit'][zaman] = 0
        for kayit in trafik['gonderilen'].index: #20
            if veriler[veri].loc()[kayit]['tcp.seq'] == 'nan' or veriler[veri].loc()[kayit]['tcp.len'] == 'nan': continue
            try:
                trafik['akisim']['uzay_ekseni'][ ( veriler[veri].loc()[kayit]['tcp.time_relative'] * zaman_carpani).astype(int)] = trafik['gonderilen'].loc()[kayit]['tcp.seq']
                trafik['akisim']['aktarilan_bit'][ ( veriler[veri].loc()[kayit]['tcp.time_relative'] * zaman_carpani).astype(int)] += trafik['gonderilen'].loc()[kayit]['tcp.len'] 
            except Exception as hata:
                print(dosyaAdlari[veri],'  -  ',veri, '   -   ', hata)
#    tumakislar.append([dosyaAdlari[veri], veri, akislar])
        kalinan_yer = trafik['akisim']['uzay_ekseni'][ilk]
        for zaman in zaman_ekseni:
            if zaman not in trafik['akisim']['uzay_ekseni']: trafik['akisim']['uzay_ekseni'][zaman] = kalinan_yer
            else: kalinan_yer = trafik['akisim']['uzay_ekseni'][zaman]
        uzay_ekseni = []
        aktarilan_bit = []
        islem_zamani = []
        for zaman in zaman_ekseni:
            uzay_ekseni.append(trafik['akisim']['uzay_ekseni'][zaman])
            aktarilan_bit.append(trafik['akisim']['aktarilan_bit'][zaman])
            islem_zamani.append(islemZamani + dt.timedelta(milliseconds=int(zaman)))
        if uzay_ekseni[-1] < 250000: continue
        print(len(islem_zamani),'   -   ',len(uzay_ekseni),'   -   ',len(zaman_ekseni))
        resim = plt.figure('UzayZamansal', figsize=(32,24))
        plt.gca().xaxis.set_major_formatter(md.DateFormatter("%H:%M:%S.%f"))
#        plt.gcf().autofmt_xdate()
        sc = plt.scatter(islem_zamani,uzay_ekseni,c=aktarilan_bit, cmap='jet_r', vmin=0, vmax=6000)
        plt.colorbar(sc)
        plt.xlabel('Zaman')
        plt.ylabel('Sequence (Bit)')
        plt.subplots_adjust(bottom=0.2)
        plt.xticks( rotation=25 )
        plt.title(dosyaAdlari[veri] + ' : Uzay-Zamansal Eğri - Akış : ' + str(akis[0]) + ', Protokol : Kaynak>' + str(trafik['gonderilen'].tail(1)['tcp.srcport'].values[0]) + ' Hedef>' + str(trafik['gonderilen'].tail(1)['tcp.dstport'].values[0]))
        plt.legend()
        plt.show()
        resim.savefig('resimler/'+dosyaAdlari[veri].replace('.csv','')+'/Uzay-Zamansal_Akis_' + str(akis[0]) + '_port_'+str(trafik['gonderilen'].tail(1)['tcp.dstport'].values[0])+'_'+ str(trafik['gonderilen'].tail(1)['tcp.dstport'].values[0])+'.png')
        plt.close(resim)

# Yalnızca belirli bir zaman parçasını kullan

def Resim_isle(islem_zamani,uzay_ekseni,aktarilan_bit,dosyaAdi, kaynak, hedef, islenenAkis):
    resim = plt.figure('UzayZamansal', figsize=(32,24))
    plt.gca().xaxis.set_major_formatter(md.DateFormatter("%H:%M:%S.%f"))
#   plt.gcf().autofmt_xdate()
    sc = plt.scatter(islem_zamani,uzay_ekseni,c=aktarilan_bit, cmap='jet_r', vmin=0, vmax=6000)
    plt.colorbar(sc)
    plt.xlabel('Zaman')
    plt.ylabel('Sequence (Bit)')
    plt.subplots_adjust(bottom=0.2)
    plt.xticks( rotation=25 )
    plt.title(dosyaAdi + ' : Uzay-Zamansal Eğri - Akış : ' + str(akis[0]) + ', Protokol : Kaynak>' + kaynak + ' Hedef>' + hedef)
    plt.legend()
    plt.show()
    resim.savefig('resimler/'+dosyaAdi.replace('.csv','')+'_Uzay-Zamansal_Akis_' + islenenAkis + '_port_'+kaynak+'_'+ hedef+'.png')
    plt.close(resim)

def Resim_isle2(islem_zamani,uzay_ekseni,aktarilan_bit,dosyaAdi, kaynak, hedef, islenenAkis,sirasi):
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

# NORMAL VERİ İŞLEME BÖLÜMÜDÜR

zaman_carpani = 1
aralik='2018 18:2' #, baslangic='Feb 15, 2018 16:20', bitis='Feb 15, 2018 18:45'
baslangic = dt.datetime.strptime('Feb 15, 2018 16:20:00.000000000 +03','%b %d, %Y %H:%M:%S.%f000 %Z')
bitis = dt.datetime.strptime('Feb 15, 2018 18:45:59.999999000 +03','%b %d, %Y %H:%M:%S.%f000 %Z')
zaman_ekseni = np.arange(0,(bitis - baslangic).total_seconds() * zaman_carpani)

mode = 0o777
zaman_kaydirici = 0
isParcalari = []
veriAkislar = []

toplamSure = time.time()
for veri in normalVeriler:
    akislar = []
    for akis in normalVeriler[veri].groupby('tcp.stream'):
        if len(akis[1]) > 50:
            akislar.append([akis[0],len(akis[1])])
    akislar.sort(key=ikinciyiAl, reverse=True)
#    dosyaAdlari.pop(dosyaAdlari.index('.csv'))
#    if os.path.isdir('resimler/'+dosyaAdlari[veri].replace('.csv','')) is False:
#        os.mkdir('resimler/'+dosyaAdlari[veri].replace('.csv',''), mode = mode, dir_fd = None)
    for akis in akislar:
        basla = time.time()
        trafik = {'alinan': [], 'gonderilen': [], 'akisim': {'uzay_ekseni':{}, 'aktarilan_bit':{}, 'islem_zamani':{}}}
        trafik['alinan'] = normalVeriler[veri].loc[ ( normalVeriler[veri]['tcp.stream'] == int(akis[0]) ) & ( normalVeriler[veri]['tcp.seq'] < normalVeriler[veri]['tcp.ack'] )]
        trafik['gonderilen'] = normalVeriler[veri].loc[ ( normalVeriler[veri]['tcp.stream'] == int(akis[0]) ) & ( normalVeriler[veri]['tcp.seq'] > normalVeriler[veri]['tcp.ack'] )]
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
        elif SonislemZamani > bitis :
            SonislemZamani = bitis
        for zaman in zaman_ekseni:
            trafik['akisim']['aktarilan_bit'][zaman] = 0
        for kayit in trafik['gonderilen'].index: #26
            kayit_zamani = dt.datetime.strptime(normalVeriler[veri].loc()[kayit]['frame.time'],'%b %d, %Y %H:%M:%S.%f000 %Z')
            baslangictan_bu_yana = kayit_zamani - baslangic
            if normalVeriler[veri].loc()[kayit]['tcp.seq'] == 'nan' or normalVeriler[veri].loc()[kayit]['tcp.len'] == 'nan' or dt.datetime.strptime(normalVeriler[veri].loc()[kayit]['frame.time'],'%b %d, %Y %H:%M:%S.%f000 %Z') < baslangic or dt.datetime.strptime(normalVeriler[veri].loc()[kayit]['frame.time'],'%b %d, %Y %H:%M:%S.%f000 %Z') > bitis: continue
            try:
                trafik['akisim']['uzay_ekseni'][int(baslangictan_bu_yana.total_seconds()*zaman_carpani)] = trafik['gonderilen'].loc()[kayit]['tcp.seq']
                trafik['akisim']['aktarilan_bit'][int(baslangictan_bu_yana.total_seconds()*zaman_carpani)] += trafik['gonderilen'].loc()[kayit]['tcp.len'] 
            except Exception as hata: #33
                print(dosyaAdlari[veri],'  -  ',veri, '   -   ', kayit,'   -   ', hata)
#    tumakislar.append([dosyaAdlari[veri], veri, akislar])
        if len(trafik['akisim']['uzay_ekseni']) < 50: continue
        kalinan_yer = trafik['akisim']['uzay_ekseni'][ilk]
        for zaman in zaman_ekseni:
            if int(zaman) not in trafik['akisim']['uzay_ekseni']: trafik['akisim']['uzay_ekseni'][int(zaman)] = kalinan_yer #37
            else: kalinan_yer = trafik['akisim']['uzay_ekseni'][zaman]
        uzay_ekseni = []
        aktarilan_bit = []
        islem_zamani = []
        for zaman in zaman_ekseni: #43
#            if trafik['akisim']['uzay_ekseni'][zaman] > 999999: continue
            uzay_ekseni.append(trafik['akisim']['uzay_ekseni'][zaman])
            aktarilan_bit.append(trafik['akisim']['aktarilan_bit'][zaman])
            islem_zamani.append(islemZamani + dt.timedelta(milliseconds=int(zaman)))
        if uzay_ekseni[-1] < 50000: continue
        print(veri,' - ', dosyaAdlari[veri],'   -   ',len(islem_zamani),'   -   ',len(uzay_ekseni),'   -   ', (time.time() - basla))
        veriAkislar.append([islem_zamani,uzay_ekseni,aktarilan_bit,dosyaAdlari[veri],str(trafik['gonderilen'].tail(1)['tcp.srcport'].values[0]),str(trafik['gonderilen'].tail(1)['tcp.dstport'].values[0]),str(akis[0])])
#        isParcalari.append(threading.Thread(target=Resim_isle, args=(islem_zamani,uzay_ekseni,aktarilan_bit,dosyaAdlari[veri],str(trafik['gonderilen'].tail(1)['tcp.srcport'].values[0]),str(trafik['gonderilen'].tail(1)['tcp.dstport'].values[0]),str(akis[0]),)))
# YAZDIRMA BÖLÜMÜDÜR
#
    fig, ax = plt.subplots(figsize=(32,24))
    eksenler = []
    if len(veriAkislar):
        for sirasi,veriAkis in enumerate(veriAkislar):
            Resim_isle2(veriAkis[0],veriAkis[1],veriAkis[2],dosyaAdlari[veri],str(trafik['gonderilen'].tail(1)['tcp.srcport'].values[0]), str(trafik['gonderilen'].tail(1)['tcp.dstport'].values[0]),str(akis[0]),sirasi)
    #        yayinla = pd.DataFrame({'İşlem Zamanı':islem_zamani,'Sequence(Bit)':uzay_ekseni,'Renk Paleti':aktarilan_bit})
    #        eksenler.append(yayinla.plot(x='İşlem Zamanı',y='Sequence(Bit)',c='Renk Paleti',kind='scatter',marker='o', cmap='jet_r', vmin=0, vmax=6000,label='Uzay-Zamansal Eğri '+dosyaAdlari[veri]+'_'+str(akis[0])+'_'+str(trafik['gonderilen'].tail(1)['tcp.srcport'].values[0])+'_'+str(trafik['gonderilen'].tail(1)['tcp.dstport'].values[0])))
        fig.savefig('resimler/Uzay-Zamansal_Akislar_'+dosyaAdlari[veri].replace('.csv','')+'.png')
        plt.close(fig)
#yayinla = pd.DataFrame({'İşlem Zamanı':islem_zamani,'Sequence(Bit)':uzay_ekseni,'Renk Paleti':aktarilan_bit})

#################################
# SALDIRI VERİSİ İŞLEME BÖLÜMÜDÜR
def saldiri_verisi_isle(saldiriVerisi, hata_noktasi=0, aralik='2018 15:4', baslangic='Mar 2, 2018 15:46', bitis='Mar 2, 2018 15:59', zaman_carpani=1):
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
        if veri < hata_noktasi: continue
        akislar = []
        for akis in saldiriVerisi[veri].groupby('tcp.stream'):
            if len(akis[1]) > 50:
                akislar.append([akis[0],len(akis[1])])
        akislar.sort(key=ikinciyiAl, reverse=True) # satır 15
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
            elif SonislemZamani > bitis :
                SonislemZamani = bitis
            for zaman in zaman_ekseni:
                trafik['akisim']['aktarilan_bit'][zaman] = 0
            for kayit in trafik['gonderilen'].index: #35
                kayit_zamani = dt.datetime.strptime(saldiriVerisi[veri].loc()[kayit]['frame.time'],'%b %d, %Y %H:%M:%S.%f000 %Z')
                baslangictan_bu_yana = kayit_zamani - baslangic
                if saldiriVerisi[veri].loc()[kayit]['tcp.seq'] == 'nan' or saldiriVerisi[veri].loc()[kayit]['tcp.len'] == 'nan' or dt.datetime.strptime(saldiriVerisi[veri].loc()[kayit]['frame.time'],'%b %d, %Y %H:%M:%S.%f000 %Z') < baslangic or dt.datetime.strptime(saldiriVerisi[veri].loc()[kayit]['frame.time'],'%b %d, %Y %H:%M:%S.%f000 %Z') > bitis: continue
                try:
                    trafik['akisim']['uzay_ekseni'][int(baslangictan_bu_yana.total_seconds()*zaman_carpani)] = trafik['gonderilen'].loc()[kayit]['tcp.seq']
                    trafik['akisim']['aktarilan_bit'][int(baslangictan_bu_yana.total_seconds()*zaman_carpani)] += trafik['gonderilen'].loc()[kayit]['tcp.len'] 
                except Exception as hata: # satır 42
                    print(dosyaAdlari[veri],'  -  ',veri, '   -   ', kayit,'   -   ', hata)
    #    tumakislar.append([dosyaAdlari[veri], veri, akislar])
            if len(trafik['akisim']['uzay_ekseni']) < 50: continue
            kalinan_yer = trafik['akisim']['uzay_ekseni'][ilk]
            for zaman in zaman_ekseni:
                if int(zaman) not in trafik['akisim']['uzay_ekseni']: trafik['akisim']['uzay_ekseni'][int(zaman)] = kalinan_yer #37
                else: kalinan_yer = trafik['akisim']['uzay_ekseni'][zaman]
            uzay_ekseni = []
            aktarilan_bit = []
            islem_zamani = []
            for zaman in zaman_ekseni: # satır 52
    #            if trafik['akisim']['uzay_ekseni'][zaman] > 999999: continue
                uzay_ekseni.append(trafik['akisim']['uzay_ekseni'][zaman])
                aktarilan_bit.append(trafik['akisim']['aktarilan_bit'][zaman])
                islem_zamani.append(islemZamani + dt.timedelta(milliseconds=int(zaman)))
            if uzay_ekseni[-1] < 50000: continue
            print(veri,' - ', dosyaAdlari[veri],'   -   ',len(islem_zamani),'   -   ',len(uzay_ekseni),'   -   ', (time.time() - basla))
            veriAkislar.append([islem_zamani,uzay_ekseni,aktarilan_bit,dosyaAdlari[veri],str(trafik['gonderilen'].tail(1)['tcp.srcport'].values[0]),str(trafik['gonderilen'].tail(1)['tcp.dstport'].values[0]),str(akis[0])])
    return veriAkislar

#DEĞİŞKENİ YEDEKLE
for veriAkis in veriAkislar:
    with open('23-02-2018-veriAkislar-degiskeni/'+veriAkis[3].replace('.csv','')+'_'+veriAkis[6].replace('.','')+'_'+'-22-3'+'.pkl', 'wb') as file:
        pickle.dump(veriAkis, file)

#bitis = dt.datetime.strptime('Mar 2, 2018 15:47:00.999999000 +03','%b %d, %Y %H:%M:%S.%f000 %Z')

#Bilgisayar Adlarıyla süzerek resimleştirme yöntem denemesi
bilgAdlari = []
for veriAkis in veriAkislar:
    if veriAkis[3].split('.')[0]+'-'+str(veriAkis[3].split('.')[2]) not in bilgAdlari:
        bilgAdlari.append(veriAkis[3].split('.')[0]+'-'+str(veriAkis[3].split('.')[2]))

for bilg in bilgAdlari:
    veriVar = 0
    fig, ax = plt.subplots(figsize=(6,8))
    for sirasi,veriAkis in enumerate(veriAkislar):
        if veriAkis[0][0] > bitis: continue
        if veriAkis[3].split('.')[0]+'-'+str(veriAkis[3].split('.')[2]) == bilg:
            veriVar = 1
            Resim_isle2(veriAkis[0], veriAkis[1], veriAkis[2], veriAkis[3], veriAkis[4], veriAkis[5], veriAkis[6], sirasi)
#    plt.ylim([96000,995000])
    if veriVar == 1:
        fig.savefig('Proje_Eski_Ciktilar/resimler18-zamanparcasi1-2Mart2018-saat-1547-1559-pcBazli/2Mart1547_Uzay-Zamansal_Akislar_'+bilg+'.png')
    plt.close(fig)

#Bilgisayar Adlarıyla süzerek resimleştirme yöntem denemesi
#100K-950K paket boyutuna sabitlenmiş akış verileri.

fig, ax = plt.subplots(figsize=(6,8))
resim = 0
for sirasi,veriAkis in enumerate(veriAkislar):
    basla = time.time()
#    for uzay, uzayVeri in enumerate(veriAkis[1]):
#        if uzayVeri > 950000:
#            cikart2 = veriAkis[1].pop(uzay)
#            cikart1 = veriAkis[0].pop(uzay)
#            cikart3 = veriAkis[2].pop(uzay)
    resim += 1
    if veriAkis[0][0] > bitis: continue
    print(sirasi,' - ',veriAkis[3],' işleniyor. ', time.time()-basla, ' sürede işlendi.')
    Resim_isle2(veriAkis[0], veriAkis[1], veriAkis[2], veriAkis[3], veriAkis[4], veriAkis[5], veriAkis[6], sirasi)
    if veriAkislar[-1][3] == veriAkis[3]:
#    if resim % 1 == 0:
        plt.ylim([96000,995000])
        fig.savefig('resimler19/2Mart2230_Uzay-Zamansal_'+veriAkis[3].replace('.csv','')+'_'+veriAkis[6].replace('.0','')+'.png')
        plt.close(fig)
        fig, ax = plt.subplots(figsize=(6,8))

# veriler15subat
# veriAkislar15subat2230
# veriler16subat
# veriAkislar16subat2230

print('İşlenme Bitti: ',(time.time() - toplamSure),'İş Parçaları başlatılıyor...')
sira = 0
for isParcasi in isParcalari:
    sira += 1
    isParcasi.start()
    isParcasi.join()


#veriler[323].loc()[veriler[323].loc[ ( veriler[323]['tcp.stream'] == 7016 ) & ( veriler[323]['tcp.seq'] > veriler[323]['tcp.ack'] )].index[0:25]][['frame.time','tcp.len','tcp.seq','tcp.ack','tcp.stream','tcp.srcport','tcp.dstport']]

