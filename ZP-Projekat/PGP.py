import datetime
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QRadioButton, QVBoxLayout, QWidget, QMessageBox, \
    QLineEdit, QLabel, QFormLayout, QDialog, QTableWidgetItem, QHeaderView, QTableWidget, QFileDialog

import PGPsend
from JavniPrsten import generisanjeRSAparaKljuceva, generisanjeJavnogKljucaPrstena, JavniPrsten, citajIzPema
from PGPreceive import prijemPoruke
#from PGPsend import generisanjePoruke
from PrivatniPrsten import generisanjePrivatnogKljucaPrstena
import PrivatniPrsten
import JavniPrsten

privatniPrstenovi = []
javniPrstenovi = []


class PopupJavniPrstenovi(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Javni prstenovi')
        self.setGeometry(1000, 100, 800, 600)

        layout = QFormLayout()
        tableHeaders = ['Datum', 'ID Kljuca', 'Javni kljuc', 'Mail', 'Ime korisnika', 'Eksportuj u .pem']
        self.tableWidget = QTableWidget()
        self.tableWidget.setColumnCount(6)
        self.tableWidget.setHorizontalHeaderLabels(tableHeaders)

        self.tableWidget.setRowCount(len(javniPrstenovi))

        for i, prsten in enumerate(javniPrstenovi):
            iPom = i
            prstenPom = prsten
            upisUPemPub = QPushButton('Upisi u .pem fajl', self)
            upisUPemPub.clicked.connect(
                lambda _, i=iPom, prsten=prstenPom: self.upisiUPemPub(i, 'PubPemFile' + prsten.keyID.hex() +'_'+ prsten.userID+'.pem'))

            self.tableWidget.setItem(i, 0, QTableWidgetItem(
                datetime.datetime.fromtimestamp(prsten.timestamp / 1000).strftime("%Y-%m-%d %H:%M:%S")))
            self.tableWidget.setItem(i, 1, QTableWidgetItem(prsten.keyID.hex()))
            self.tableWidget.setItem(i, 2, QTableWidgetItem(prsten.publicKey.hex()))
            self.tableWidget.setItem(i, 3, QTableWidgetItem(prsten.userID))
            self.tableWidget.setItem(i, 4, QTableWidgetItem(prsten.user))
            self.tableWidget.setCellWidget(i, 5, upisUPemPub)

        self.tableWidget.horizontalHeader().setStretchLastSection(True)
        self.tableWidget.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch)

        layout.addWidget(self.tableWidget)
        self.setLayout(layout)

    def upisiUPemPub(self, i, file):
        prsten = javniPrstenovi[i]
        prsten.upisiUPem(file)

class SlanjePoruke(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Posalji poruku')
        self.setGeometry(1000, 100, 800, 600)
        layout = QFormLayout()
        label = QLabel("Unesite sifru:")
        layout.addWidget(label)
        self.textboxSifra = QLineEdit()
        layout.addWidget(self.textboxSifra)
        label1 = QLabel("Unesite mejl posiljalaca poruke:")
        layout.addWidget(label1)
        self.textboxMejlPos = QLineEdit()
        layout.addWidget(self.textboxMejlPos)
        label2 = QLabel("Unesite mejl primalaca poruke:")
        layout.addWidget(label2)
        self.textboxMejlPrim = QLineEdit()
        layout.addWidget(self.textboxMejlPrim)
        label3 = QLabel("Unesite sadrzaj poruke:")
        layout.addWidget(label3)
        self.textboxPoruka = QLineEdit()
        layout.addWidget(self.textboxPoruka)
        label4 = QLabel("Izaberite algoritam:")
        layout.addWidget(label4)

        self.radio1 = QRadioButton("AES", self)
        self.radio1.value = 'AES'
        self.radio2 = QRadioButton("CAST", self)
        self.radio2.value = 'CAST'
        layout.addWidget(self.radio1)
        layout.addWidget(self.radio2)
        #label4 = QLabel("Unesite ime fajla za cuvanje:")
        #layout.addWidget(label4)
        #self.textboxFajl = QLineEdit()
        #layout.addWidget(self.textboxFajl)

        send = QPushButton('Posalji', self)



        send.clicked.connect(self.posalji)
        layout.addWidget(send)
        self.setLayout(layout)
    def posalji(self):
        algoritam = 'AES' if self.radio1.isChecked() else 'CAST'
        now = datetime.datetime.now()
        now_str = now.strftime("%Y-%m-%d %H_%M_%S")
        fajl = 'Poruka' + self.textboxMejlPos.text() + self.textboxMejlPrim.text() + now_str + '.txt'
        p = PGPsend.generisanjePoruke(self.textboxSifra.text(),self.textboxMejlPos.text(),self.textboxMejlPrim.text(),
                                      self.textboxPoruka.text(),fajl,privatniPrstenovi,javniPrstenovi, algoritam)
        if(p != None) :
            QMessageBox.information(self, 'Info', f'Poruka: {'Uspesno poslata poruka'}')
        if(p == None) :
            QMessageBox.information(self, 'Info', f'Poruka: {'Neuspesno poslata poruka'}')
class PopupPrivatniPrstenovi(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Privatni prstenovi')
        self.setGeometry(1000, 100, 800, 600)

        layout = QFormLayout()
        tableHeaders = ['Datum', 'ID Kljuca', 'Javni kljuc', 'Privatni kljuc', 'Mail', 'Ime korisnika',
                        'Eksportuj u .pem']
        self.tableWidget = QTableWidget()
        self.tableWidget.setColumnCount(7)
        self.tableWidget.setHorizontalHeaderLabels(tableHeaders)

        self.tableWidget.setRowCount(len(privatniPrstenovi))

        for i, prsten in enumerate(privatniPrstenovi):
            iPom = i
            prstenPom = prsten
            upisUPemPriv = QPushButton('Upisi u .pem fajl', self)
            upisUPemPriv.clicked.connect(
                lambda _, i=iPom, prsten=prstenPom: self.upisiUPemPriv(i, 'PrivPemFile' + prsten.keyID.hex() + '_' + prsten.userID + '.pem'))

            # upisUPemPriv.clicked.connect(lambda: self.upisiUPemPriv(i,'PrivPemFile' + prsten.keyID.hex() + '.pem'))
            self.tableWidget.setItem(i, 0, QTableWidgetItem(
                datetime.datetime.fromtimestamp(prsten.timestamp / 1000).strftime("%Y-%m-%d %H:%M:%S")))
            self.tableWidget.setItem(i, 1, QTableWidgetItem(prsten.keyID.hex()))
            self.tableWidget.setItem(i, 2, QTableWidgetItem(prsten.publicKey.hex()))
            self.tableWidget.setItem(i, 3, QTableWidgetItem(prsten.privateKey.hex()))
            self.tableWidget.setItem(i, 4, QTableWidgetItem(prsten.userID))
            self.tableWidget.setItem(i, 5, QTableWidgetItem(prsten.user))
            self.tableWidget.setCellWidget(i, 6, upisUPemPriv)

        self.tableWidget.horizontalHeader().setStretchLastSection(True)
        self.tableWidget.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch)

        layout.addWidget(self.tableWidget)
        self.setLayout(layout)

    def upisiUPemPriv(self, i, file: str):
        prsten = privatniPrstenovi[i]
        prsten.upisiUPem(file)


class PrimljenaPoruka(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.file_path = None
        self.setWindowTitle('Otvori poruku')
        self.setGeometry(1000, 100, 800, 600)
        layout = QFormLayout()
        label = QLabel("Unesite sifru:")
        layout.addWidget(label)
        self.textboxSifra = QLineEdit()


        file = QPushButton('Primljena poruka')
        file.clicked.connect(self.otvoriFajl)
        send = QPushButton('Otvori poruku', self)


        send.clicked.connect(self.otvori)
        layout.addWidget(file)
        layout.addWidget(self.textboxSifra)
        layout.addWidget(send)
        self.setLayout(layout)
    def otvori(self):
        if(self.file_path == None):
            return
        poruka = prijemPoruke(self.textboxSifra.text(),self.file_path,privatniPrstenovi,javniPrstenovi)
        QMessageBox.information(self, 'Info', f'Poruka je: {poruka}')
    def otvoriFajl(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        self.file_path, _ = QFileDialog.getOpenFileName(self, "Select a File", "", "Moje_zasticene_poruke(*.txt)", options=options)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setGeometry(100, 100, 1000, 800)
        self.setWindowTitle('PGP')

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        labelIzaberi = QLabel('Izaberite velicinu kljuca:')
        layout.addWidget(labelIzaberi)

        self.radio1 = QRadioButton('1024', self)
        self.radio1.value = 1024

        self.radio2 = QRadioButton('2048', self)
        self.radio2.value = 2048

        layout.addWidget(self.radio1)
        layout.addWidget(self.radio2)
        label = QLabel("Unesite mail:")
        layout.addWidget(label)
        self.textboxMail = QLineEdit()
        layout.addWidget(self.textboxMail)
        label1 = QLabel("Unesite ime:")
        layout.addWidget(label1)
        self.textboxIme = QLineEdit()
        layout.addWidget(self.textboxIme)
        label2 = QLabel("Unesite lozinku koja stiti privatni kljuc:")
        layout.addWidget(label2)
        self.textboxLozinka = QLineEdit()
        layout.addWidget(self.textboxLozinka)

        complete_button = QPushButton('Generisi kljuc', self)
        complete_button.clicked.connect(self.on_complete_click)
        prikaz_javnogPrstena = QPushButton('Prikaz javnih prstenova', self)
        prikaz_javnogPrstena.clicked.connect(self.prikazJavnogPrstena)
        prikaz_privatnogPrstena = QPushButton('Prikaz privatnih prstenova', self)
        prikaz_privatnogPrstena.clicked.connect(self.prikazPrivatnogPrstena)
        dugmeImportPriv = QPushButton('Ucitaj iz .pem privatnog prstena', self)
        dugmeImportPriv.clicked.connect(self.upload_button)
        dugmeImportPub = QPushButton('Ucitaj iz .pem javnog prstena', self)
        dugmeImportPub.clicked.connect(self.upload_button1)
        dugmePosaljiPoruku = QPushButton('Posalji poruku', self)
        dugmePosaljiPoruku.clicked.connect(self.posaljiPoruku)
        dugmePrimiPoruku = QPushButton('Primljena poruka', self)
        dugmePrimiPoruku.clicked.connect(self.receive)

        layout.addWidget(complete_button)
        layout.addWidget(prikaz_javnogPrstena)
        layout.addWidget(prikaz_privatnogPrstena)
        layout.addWidget(dugmeImportPriv)
        layout.addWidget(dugmeImportPub)
        layout.addWidget(dugmePosaljiPoruku)
        layout.addWidget(dugmePrimiPoruku)
    def receive(self):
        self.popup = PrimljenaPoruka(self)
        self.popup.exec_()
    def posaljiPoruku(self):
        self.popup = SlanjePoruke(self)
        self.popup.exec_()



    def upload_button1(self):
        flag = False
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a File", "", "Pem Files (*.pem)",
                                                   options=options)
        if file_path:

            prsten = JavniPrsten.citajIzPema(file_path)
            if prsten==None:
                QMessageBox.information(self, 'Info', f'Prsten: {'NEISPRAVAN PEM FAJL ZA JAVNI PRSTEN'}')
                return

            for i in range(len(javniPrstenovi)):
                if (prsten.keyID == javniPrstenovi[i].keyID):
                    flag = True
                    print('Prsten sa ID kljuca ' + prsten.keyID.hex() + ' vec postoji')
            if (flag == False):
                javniPrstenovi.append(prsten)

    def upload_button(self):
        flag = False
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a File", "", "Pem Files (*.pem)",
                                                   options=options)
        if file_path:

            prsten = PrivatniPrsten.citajIzPema(file_path)
            if prsten==None:
                QMessageBox.information(self, 'Info', f'Prsten: {'NEISPRAVAN PEM FAJL ZA PRIVATNI PRSTEN'}')
                return

            for i in range(len(privatniPrstenovi)):
                if (prsten.keyID == privatniPrstenovi[i].keyID):
                    flag = True
                    print('Prsten sa ID kljuca ' + prsten.keyID.hex() + ' vec postoji')
            if (flag == False):
                privatniPrstenovi.append(prsten)

    def prikazPrivatnogPrstena(self):
        self.popup = PopupPrivatniPrstenovi(self)
        self.popup.exec_()

    def prikazJavnogPrstena(self):
        self.popup = PopupJavniPrstenovi(self)
        self.popup.exec_()

    def on_complete_click(self):
        if self.radio1.isChecked():

            RSAKljuc = generisanjeRSAparaKljuceva(self.radio1.value)

            javniPrsten = generisanjeJavnogKljucaPrstena(RSAKljuc, self.textboxMail.text(), self.textboxIme.text())
            privatniPrsten = generisanjePrivatnogKljucaPrstena(RSAKljuc, self.textboxMail.text(),
                                                               self.textboxLozinka.text(), self.textboxIme.text())
            javniPrstenovi.append(javniPrsten)
            privatniPrstenovi.append(privatniPrsten)
            QMessageBox.information(self, 'Info', f'Prsten: {'Uspesno kreiran prsten velicina 1024'}')

        elif self.radio2.isChecked():

            RSAKljuc = generisanjeRSAparaKljuceva(self.radio2.value)

            javniPrsten = generisanjeJavnogKljucaPrstena(RSAKljuc, self.textboxMail.text(), self.textboxIme.text())
            privatniPrsten = generisanjePrivatnogKljucaPrstena(RSAKljuc, self.textboxMail.text(),
                                                               self.textboxLozinka.text(), self.textboxIme.text())
            javniPrstenovi.append(javniPrsten)
            privatniPrstenovi.append(privatniPrsten)
            QMessageBox.information(self, 'Info', f'Prsten: {'Uspesno kreiran prsten velicine 2048'}')

        else:
            QMessageBox.information(self, 'Selection', 'No option is selected')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())


