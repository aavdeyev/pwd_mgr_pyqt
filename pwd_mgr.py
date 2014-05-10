#!/usr/bin/python

import sys
import imp
import os
import MySQLdb
import getopt
import getpass
import warnings
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from Crypto.Cipher import DES

#####################################################################
######################################################################
## Password Management tool
##
## Usage:
##
## To add a new user:
##     pwd_mgr     -a -u <user> -p <password> -d <description text> 
##             [-c <comments>]
##
## To list users:
##     pwd_mgr     -l
##
## To edit a user:
##     pwd_mgr     -e -i user_index [-u <user>] [-p <new password>] 
##             [-d <new descr>] [-c <new comment>]
##
## To remove a user from database:
##     pwd_mgr     -r -i <user index>
##
## To specify security key from cmd line add -s <key> option
##    
#######################################################################
#######################################################################

######################################################################
#
# The global proc to encrypt a string using DES8
#
######################################################################

def encryptStrDES8(strText, securityKey):

    # Since DES8 will only work with byte octets, we need to right-pad
    # the security key and the string 
    securityKey = str(securityKey)
    # The max allowed security key for this encryption type is 8,
    # so we will right-pad securityKey to 8
    securityKey = securityKey.ljust(8)

    strText = str(strText)
    # Right-pad the string to the multiple of 8
    ljust_size = ((len(strText) / 8) + 1) * 8
    strText = strText.ljust(ljust_size)

    des = DES.new(securityKey, DES.MODE_ECB)
    strEncryptDes = des.encrypt(strText)
    strEncryptDesASCII = strEncryptDes.encode('hex')
    
    return strEncryptDesASCII
          
######################################################################
#
# The global proc to decrypt a DES8-encrypted string
#
#####################################################################

def decryptStrDES8(strEncryptASCII, securityKey):

    # Since DES8 will only work with byte octets, we need to right-pad
    # the security key before passing it over to DES
    securityKey = str(securityKey)
    securityKey = securityKey.ljust(8)

    des = DES.new(securityKey, DES.MODE_ECB)
    strEncryptDes = strEncryptASCII.decode('hex')
    strDecr = des.decrypt(strEncryptDes)
 
    # The string we get from DEC may have some trailing spaces, because 
    # DES only works with byte octets, and we need to strip them off here
    strDecr = strDecr.strip()

    return strDecr

##################################################################
##
## The class to manage configuration file
##
##################################################################

class cfgFile(object):

   #--------------------------------------------------------------  
   # The proc to build the path for configuration file
   #--------------------------------------------------------------

    def path(self):
    
        # Get current script dir
        self.scriptDir = os.path.dirname(os.path.abspath(__file__))
        # Get current script name
        self.scriptName = os.path.basename(__file__)
        # Strip off extension
        self.scriptNameBase = os.path.splitext(self.scriptName)[0]
        # Build config file name
        self.configFileName = self.scriptNameBase + "." + "cfg"
        # Build full path for the config file
        self.configFilePath = os.path.join(self.scriptDir,\
                self.configFileName)

        return self.configFilePath

    #-------------------------------------------------------------
    # The proc to check if configuration file already exists
    #-------------------------------------------------------------

    def exists(self):
            
        return os.path.isfile(self.path())

    #--------------------------------------------------------------    
    # The proc to read settings from the configuration file    
    #--------------------------------------------------------------

    def read(self, securityKey):
        
        # Open config file for reading
        self.cfgFileHandle = open(self.path(), 'r')

        # Read line by line and dynamically execute each line
        # The lines should be:
        #    dbUserEncryptHex = "<hex>"
        #    dbPasswdEcryptHex = "<hex>"
        # The execution will result in respective variable assignment
        for line in self.cfgFileHandle:
            exec(line)

        self.cfgFileHandle.close()
      
        # Decrypt the user and password using security key
        curMySQLUser = decryptStrDES8(dbUserEncryptHex,\
                securityKey)
        curMySQLPasswd = decryptStrDES8(dbPasswdEncryptHex,\
                securityKey)

        # Return decrypted user and password in a dictionary
        curCfg = dict(mysqlUser = curMySQLUser,\
                mysqlPasswd = curMySQLPasswd)

        return curCfg
    
    #----------------------------------------------------------------    
    # The proc to update the configuration file with the new settings
    #-----------------------------------------------------------------    

    def update(self, cfgData, securityKey):

        # Encrypt user name and password
        newUserEncryptHex = encryptStrDES8(cfgData["mysqlUser"],\
                securityKey)
        newPasswdEncryptHex = encryptStrDES8(cfgData["mysqlPasswd"],\
                securityKey)
        
        # Open configuration file for writing         
        self.cfgFileHandle = open(self.path(), 'w')
        # Write down encrypted user name and password        
        self.cfgFileHandle.write("dbUserEncryptHex = " + "'" +\
                newUserEncryptHex + "'" + "\n")
        self.cfgFileHandle.write("dbPasswdEncryptHex = " + "'" +\
                newPasswdEncryptHex + "'" + "\n")

        self.cfgFileHandle.close()
            
#####################################################################
##
##
## Class to manage MySQL password db
##
##
#####################################################################

class MySQLPWDdb(object):
 
    #-----------------------------------------------------------------   
    # Constructor MySQLdb    
    #-----------------------------------------------------------------

    def __init__(self, dbName, dbTableName, dbUser, dbPasswd, securityKey):

        self.dbName = dbName
        self.dbTableName = dbTableName
        self.dbUser = dbUser
        self.dbPasswd = dbPasswd
        self.securityKey = securityKey  

        self.__db_error__ = ""
        self.__db_changes_pending__ = ""

    #------------------------------------------------------------------
    # Enable/Disable Autocommit
    #------------------------------------------------------------------

    def autocommit(self, val):

        self.dbHandle.autocommit(val)

    #------------------------------------------------------------------
    # Commit
    #------------------------------------------------------------------

    def commit(self):

        self.dbHandle.commit()

    #------------------------------------------------------------------
    # Roll back
    #------------------------------------------------------------------

    def rollback(self):

        self.dbHandle.rollback()

    #------------------------------------------------------------------    
    # Connect to MySQL database    
    #------------------------------------------------------------------

    def connect(self):

        self.__db_error__ = ""

        # Disable MySQL warnings. We expect some warnings here and 
        # don't want the user to be confused by them
        warnings.filterwarnings('ignore', category = MySQLdb.Warning)

        # Connect to MySQL
        try:
            self.mysqlHandle = MySQLdb.connect(host="localhost",\
                    user=dbUser,passwd=dbPasswd)
            self.cursor = self.mysqlHandle.cursor()
        except Exception as err:
            self.__db_error__ += "\nError connecting to MySQL: " + str(err)
            return
 
        # Create user database if doesn't exist
        try:
            self.cursor.execute("CREATE DATABASE IF NOT EXISTS %s"\
                    % (dbName) )
        except Exception as err:
            self.__db_error__ += "\nError creating MySQL database " +\
                    dbName + ":" + str(err)
            return

        # Close this MySQL connection
        self.mysqlHandle.close()

        # Connect to the database itself once it exists and create user 
        # table if it doesn't exist
        try:
            self.dbHandle = MySQLdb.connect(host="localhost",\
                    user=dbUser, passwd=dbPasswd, db=dbName)
            self.cursor = self.dbHandle.cursor()
            self.cursor.execute('CREATE TABLE IF NOT EXISTS %s \
                    (Id INT PRIMARY KEY AUTO_INCREMENT,\
                    description VARCHAR(64) NOT NULL,\
                    user_name VARCHAR(64) NOT NULL,\
                    user_password VARCHAR(64) NOT NULL,\
                    last_updated TIMESTAMP NOT NULL ON UPDATE\
                        CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\
                    comments VARCHAR(64) NOT NULL)'\
                    % (dbTableName))
        except Exception as err:
            self.__db_error__ += "\nError creating MySQL table " +\
                    dbTableName + ":" + str(err)
            return

    #------------------------------------------------------------------
    # Return MySQL Error
    #------------------------------------------------------------------

    def getError(self):

        return self.__db_error__

    #-------------------------------------------------------------------
    # Return True if there are any uncommitted changes to db, otherwise
    # return False
    #-------------------------------------------------------------------

    def changesPending(self):

        return self.__db_changes_pending__

    #-------------------------------------------------------------------
    # Reset pending changes flag to False
    #-------------------------------------------------------------------

    def clearPendingChanges(self):

        self.__db_changes_pending__ = False

    #-------------------------------------------------------------------    
    # Add record to MySQL db  
    #-------------------------------------------------------------------
    
    def addRecord(self, user, passwd, descr, comments, commit = True):

        try:
            self.cursor.execute('INSERT INTO user_passwords(description,\
                    user_name, user_password, comments)\
                    VALUES (AES_ENCRYPT("%s","%s"),\
                    AES_ENCRYPT("%s","%s"), AES_ENCRYPT("%s","%s"),\
                    AES_ENCRYPT("%s","%s"))' %\
                    (descr, self.securityKey, user, self.securityKey,\
                    passwd, self.securityKey, comments, self.securityKey))

            if commit :
                self.dbHandle.commit()                
                self.__db_changes_pending__ = False
            else :
                self.__db_changes_pending__ = True

            self.__db_error__ = ""
   
        except Exception as err:
            self.__db_error__ = str(err)
 
            if commit == False :
                self.dbHandle.rollback()
            
    #------------------------------------------------------------------    
    # Remove record from database  
    #------------------------------------------------------------------

    def removeRecord(self, index, commit = True):
     
        try:
            self.cursor.execute('DELETE from %s WHERE\
                    Id = "%s"' % (dbTableName, index))

            if commit :
                self.dbHandle.commit()               
                self.__db_changes_pending__ = False
            else :
                self.__db_changes_pending__ = True

            self.__db_error = ""
              
        except Exception as err: 
            self.__db_error__ = str(err)

            if commit :
                self.dbHandle.rollback()
           
    #------------------------------------------------------------------    
    # Edit record    
    #------------------------------------------------------------------

    def editRecord(self, index, newDescr="", newUser="", newPasswd="",\
            newComm="", commit = True):

        try:
            if newDescr :                
                self.cursor.execute('UPDATE %s SET description =\
                        AES_ENCRYPT("%s","%s")\
                        WHERE Id = "%s"'\
                        % (dbTableName, newDescr, self.securityKey,\
                        index))
            if newUser :
                self.cursor.execute('UPDATE %s SET user_name =\
                        AES_ENCRYPT("%s","%s")\
                        WHERE Id = "%s"'\
                        % (dbTableName, newUser, self.securityKey,\
                        index))
            if newPasswd :
                self.cursor.execute('UPDATE %s SET user_password =\
                        AES_ENCRYPT("%s","%s")\
                        WHERE Id = "%s"'\
                        % (dbTableName, newPasswd, self.securityKey,\
                        index))
            if newComm :
                self.cursor.execute('UPDATE %s SET comments =\
                        AES_ENCRYPT("%s","%s")\
                        WHERE Id = "%s"'\
                        % (dbTableName, newComm, self.securityKey,\
                        index))                

            if commit:
                self.dbHandle.commit()
                self.__db_changes_pending__ = False
            else:
                self.__db_changes_pending__ = True

            self.__db_error__ = ""           

        except Exception as err:

            self.__db_error__ = str(err)
 
            if commit:
                self.dbHandle.rollback() 
            
    #--------------------------------------------------------------------    
    # List all records in MySQL user database    
    #--------------------------------------------------------------------

    def listRecords(self, printStdOut = True):
 
        try:
            self.cursor.execute('SELECT Id, AES_DECRYPT(description,"%s"),\
                    AES_DECRYPT(user_name,"%s"),\
                    AES_DECRYPT(user_password,"%s"),\
                    last_updated,\
                    AES_DECRYPT(comments,"%s") FROM user_passwords ORDER BY\
                        AES_DECRYPT(description, "%s")' %\
                    (self.securityKey, self.securityKey, self.securityKey,\
                        self.securityKey, self.securityKey))
            records = self.cursor.fetchall()

            if printStdOut:
                for row in records:
                    id = row[id_column_index]
                    descr = row[descr_column_index]
                    user = row[user_column_index]
                    passwd = row[passwd_column_index]
                    last_updated = row[last_updated_column_index]
                    comments = row[comments_column_index]
                    print ("%-5s | %-25s  |  %-10s  |  %-10s | %-10s |\
                            %-10s" % (id, descr, user, passwd,\
                            last_updated, comments))

            self.__db_error__ = ""

            return records

        except Exception as err:

            self.__db_error__ = str(err)
                  
    #----------------------------------------------------------------    
    # Destructor MySQLdb    
    #----------------------------------------------------------------

    def __del__(self):

        # Close the DB when we are done
        if hasattr(self, 'dbHandle'):
            self.dbHandle.close()
        
######################################################################
#
# The class to handle the New User dialog
#
######################################################################

#---------------------------------------------------------------------
# Constructor NewUserDialog
#---------------------------------------------------------------------

class NewUserDialog(QDialog):

    def __init__(self, parent = None):
    
        super(NewUserDialog, self).__init__(parent)

        # Create Description Line edit
        self.descrLineLabel = QLabel("&Description:")
        self.descrLineEdit = QLineEdit()
        self.descrLineLabel.setBuddy(self.descrLineEdit)
        # Create User Line edit
        self.userLineLabel = QLabel("&Username:")
        self.userLineEdit = QLineEdit()
        self.userLineLabel.setBuddy(self.userLineEdit)
        # Create Password Line edit
        self.passwdLineLabel = QLabel("&Password:")
        self.passwdLineEdit = QLineEdit()
        self.passwdLineLabel.setBuddy(self.passwdLineEdit)
        # Create Comments Line edit
        self.commLineLabel = QLabel("&Comments:")
        self.commLineEdit = QLineEdit()
        self.commLineLabel.setBuddy(self.commLineEdit)
        # Create OK/Cancell button box
        self.buttonBox = QDialogButtonBox(QDialogButtonBox.Ok|\
                QDialogButtonBox.Cancel)

        # Create form layout and add button layout to it
        layout = QGridLayout()
        layout.addWidget(self.descrLineLabel, 0, 0)
        layout.addWidget(self.descrLineEdit, 0, 1)
        layout.addWidget(self.userLineLabel, 1, 0)
        layout.addWidget(self.userLineEdit, 1, 1)
        layout.addWidget(self.passwdLineLabel, 2, 0)
        layout.addWidget(self.passwdLineEdit, 2, 1)
        layout.addWidget(self.commLineLabel, 3, 0)
        layout.addWidget(self.commLineEdit, 3, 1)
        layout.addWidget(self.buttonBox, 4, 0, 1, 2)
        self.setLayout(layout)

        self.descrLineEdit.setFocus()
             
        self.connect(self.buttonBox, SIGNAL("accepted()"),
                self, SLOT("accept()"))
        self.connect(self.buttonBox, SIGNAL("rejected()"),
                self, SLOT("reject()"))

        self.setWindowTitle("New User")

    #----------------------------------------------------------------
    # The user clicked OK button
    #----------------------------------------------------------------

    def accept(self):

        if not self.descrLineEdit.text():
            QMessageBox.critical(self, "Error", "Description is required")
        elif not self.userLineEdit.text():
            QMessageBox.critical(self, "Error", "Username is required")
        elif not self.passwdLineEdit.text():
            QMessageBox.critical(self, "Error", "Password is required")
        else:    
            QDialog.accept(self)

    #-----------------------------------------------------------------
    # Return description, user, password and comment selected by user
    #-----------------------------------------------------------------

    def getData(self):
        
        return {'descr' : self.descrLineEdit.text(),\
                'user' : self.userLineEdit.text(),\
                'passwd' : self.passwdLineEdit.text(),\
                'comm' : self.commLineEdit.text()}

######################################################################
#
# The class to handle the Edit User dialog
#
######################################################################

#---------------------------------------------------------------------
# Constructor EditUserDialog
#---------------------------------------------------------------------

class EditUserDialog(QDialog):

    def __init__(self, usrInfo={}, parent = None):
    
        super(EditUserDialog, self).__init__(parent)

        # Create Description Line edit
        self.descrLineLabel = QLabel("&Description:")
        self.descrLineEdit = QLineEdit(usrInfo['descr'])
        self.descrLineEdit.selectAll()
        self.descrLineEdit.setFocus()
        self.descrLineLabel.setBuddy(self.descrLineEdit)
        # Create User Line edit
        self.userLineLabel = QLabel("&Username:")
        self.userLineEdit = QLineEdit(usrInfo['user'])
        self.userLineLabel.setBuddy(self.userLineEdit)
        # Create Password Line edit
        self.passwdLineLabel = QLabel("&Password:")
        self.passwdLineEdit = QLineEdit(usrInfo['passwd'])
        self.passwdLineLabel.setBuddy(self.passwdLineEdit)
        # Create Comments Line edit
        self.commLineLabel = QLabel("&Comments:")
        self.commLineEdit = QLineEdit(usrInfo['comm'])
        self.commLineLabel.setBuddy(self.commLineEdit)
        # Create OK/Cancell button box
        self.buttonBox = QDialogButtonBox(QDialogButtonBox.Ok|\
                QDialogButtonBox.Cancel)

        # Create form layout and add button layout to it
        layout = QGridLayout()
        layout.addWidget(self.descrLineLabel, 0, 0)
        layout.addWidget(self.descrLineEdit, 0, 1)
        layout.addWidget(self.userLineLabel, 1, 0)
        layout.addWidget(self.userLineEdit, 1, 1)
        layout.addWidget(self.passwdLineLabel, 2, 0)
        layout.addWidget(self.passwdLineEdit, 2, 1)
        layout.addWidget(self.commLineLabel, 3, 0)
        layout.addWidget(self.commLineEdit, 3, 1)
        layout.addWidget(self.buttonBox, 4, 0, 1, 2)
        self.setLayout(layout)

        self.descrLineEdit.setFocus()
             
        self.connect(self.buttonBox, SIGNAL("accepted()"),
                self, SLOT("accept()"))
        self.connect(self.buttonBox, SIGNAL("rejected()"),
                self, SLOT("reject()"))

        self.setWindowTitle("Edit User")

    #-----------------------------------------------------------------
    # The user clicked OK button
    #-----------------------------------------------------------------

    def accept(self):

        if not self.descrLineEdit.text():
            QMessageBox.critical(self, "Error", "Description is required")
        elif not self.userLineEdit.text():
            QMessageBox.critical(self, "Error", "Username is required")
        elif not self.passwdLineEdit.text():
            QMessageBox.critical(self, "Error", "Password is required")
        else:    
            QDialog.accept(self)

    #-----------------------------------------------------------------
    # Return description, user, password and comment selected by user
    #-----------------------------------------------------------------
 
    def getData(self):
        
        return {'descr' : self.descrLineEdit.text(),\
                'user' : self.userLineEdit.text(),\
                'passwd' : self.passwdLineEdit.text(),\
                'comm' : self.commLineEdit.text()}

######################################################################
#
# The class to create Edit Options dialog
#
######################################################################

#---------------------------------------------------------------------
# Constructor EditOptionsDialog
#---------------------------------------------------------------------

class EditOptionsDialog(QDialog):

    def __init__(self, cfgList = {}, parent = None):
    
        super(EditOptionsDialog, self).__init__(parent)       

        # Create MySQL User Line edit
        self.mysqlUsrLineLabel = QLabel("MySQL &User:")
        self.mysqlUsrLineEdit = QLineEdit(cfgList['mysqlUser'])        
        self.mysqlUsrLineEdit.setFocus()
        self.mysqlUsrLineLabel.setBuddy(self.mysqlUsrLineEdit)
        # Create MySQL Password Line edit
        self.mysqlPwdLineLabel = QLabel("MySQL &Password:")
        self.mysqlPwdLineEdit = QLineEdit(cfgList['mysqlPasswd'])
        self.mysqlPwdLineEdit.setEchoMode(QLineEdit.Password)
        self.mysqlPwdLineLabel.setBuddy(self.mysqlPwdLineEdit)
        # Create MySQL Re-Enter Password Line edit
        self.mysqlReEnterPwdLineLabel = QLabel("&Re-enter MySQL Password:")
        self.mysqlReEnterPwdLineEdit = QLineEdit(cfgList['mysqlPasswd'])
        self.mysqlReEnterPwdLineEdit.setEchoMode(QLineEdit.Password)
        self.mysqlReEnterPwdLineLabel.setBuddy(self.mysqlReEnterPwdLineEdit)
                
        # Create OK/Cancell button box
        self.buttonBox = QDialogButtonBox(QDialogButtonBox.Ok|\
                QDialogButtonBox.Cancel)

        # Create form layout and add button layout to it
        layout = QGridLayout()
        layout.addWidget(self.mysqlUsrLineLabel, 0, 0)
        layout.addWidget(self.mysqlUsrLineEdit, 0, 1)
        layout.addWidget(self.mysqlPwdLineLabel, 1, 0)
        layout.addWidget(self.mysqlPwdLineEdit, 1, 1)
        layout.addWidget(self.mysqlReEnterPwdLineLabel, 2, 0)
        layout.addWidget(self.mysqlReEnterPwdLineEdit, 2, 1)
                  
        layout.addWidget(self.buttonBox, 4, 0, 1, 2)
        self.setLayout(layout) 

        self.mysqlUsrLineEdit.setFocus()
             
        self.connect(self.buttonBox, SIGNAL("accepted()"),
                self, SLOT("accept()"))
        self.connect(self.buttonBox, SIGNAL("rejected()"),
                self, SLOT("reject()"))

        self.setWindowTitle("Options")

    #-----------------------------------------------------------------
    # The user clicked OK button
    #-----------------------------------------------------------------

    def accept(self):

        if not self.mysqlUsrLineEdit.text():
            QMessageBox.critical(self, "Error", "MySQL user is required")
        elif not self.mysqlPwdLineEdit.text():
            QMessageBox.critical(self, "Error", "MySQL password is required") 
        elif not self.mysqlReEnterPwdLineEdit.text():
            QMessageBox.critical(self, "Error",\
                    "Re-Enter MySQL password is required")
        elif self.mysqlPwdLineEdit.text() !=\
                self.mysqlReEnterPwdLineEdit.text():
            QMessageBox.critical(self, "Error",\
                    "The passwords you have entered do not match")
        else:    
            QDialog.accept(self)

    #-----------------------------------------------------------------
    # Return description, user, password and comment selected by user
    #-----------------------------------------------------------------

    def getData(self):
        
        return {'mysqlUser' : self.mysqlUsrLineEdit.text(),\
                'mysqlPasswd' : self.mysqlPwdLineEdit.text()}
 
######################################################################
#
# The class to handle the main (User List) dialog
#
######################################################################

#--------------------------------------------------------------------
# Constructor UserListDialog
#--------------------------------------------------------------------

class UserListDialog(QDialog):

    def __init__(self, mySQLdb, securityKey, parent = None):

        super(UserListDialog, self).__init__(parent)

        self.mySQLdb = mySQLdb
        mySQLdb.autocommit(False)

        self.securityKey = securityKey

        self.resize(self.width() * 1.5, self.height())

        # Create Table Widget               
        self.userTable = QTableWidget()
        self.userTable.clear()
        self.userTable.setSortingEnabled(True)
        
        # Create Push Buttons
        self.newButton = QPushButton("&New")
        self.newButton.setEnabled(True)
        self.newButton.setCheckable(False)
        self.newButton.setAutoDefault(False)
        self.editButton = QPushButton("&Edit")
        self.editButton.setEnabled(False)
        self.editButton.setCheckable(False)
        self.editButton.setAutoDefault(False)
        self.deleteButton = QPushButton("&Delete")
        self.deleteButton.setEnabled(False)
        self.deleteButton.setCheckable(False)
        self.deleteButton.setAutoDefault(False)
        self.saveButton = QPushButton("&Save")        
        self.saveButton.setEnabled(True)
        self.saveButton.setCheckable(False)
        self.saveButton.setAutoDefault(False)
        self.closeButton = QPushButton("&Close")
        self.closeButton.setEnabled(True)
        self.closeButton.setCheckable(False)
        self.closeButton.setAutoDefault(False)
        self.optionsButton = QPushButton("&Options")
        self.optionsButton.setEnabled(True)
        self.optionsButton.setCheckable(False)
        self.optionsButton.setAutoDefault(False)
                                           
        # Add Push Buttons to QVBoxLayout
        buttonLayout = QVBoxLayout()
        buttonLayout.addWidget(self.newButton)
        buttonLayout.addWidget(self.editButton)
        buttonLayout.addWidget(self.deleteButton)
        buttonLayout.addWidget(self.saveButton)
        buttonLayout.addWidget(self.closeButton)
        buttonLayout.addStretch()
        buttonLayout.addWidget(self.optionsButton)

        # Add Button Layout and TableWidget to the form layout
        layout = QHBoxLayout()
        layout.addWidget(self.userTable)                 
        layout.addLayout(buttonLayout)
       
        self.setLayout(layout)              
        self.setWindowTitle("Password Manager")

        self.userTable.setFocus()

        # Connect buttons to signal handlers
        self.connect(self.newButton, SIGNAL("clicked()"),\
                self.newButtonClicked)
        self.connect(self.editButton, SIGNAL("clicked()"),\
                self.editButtonClicked)
        self.connect(self.deleteButton, SIGNAL("clicked()"),\
                self.deleteButtonClicked)
        self.connect(self.saveButton, SIGNAL("clicked()"),\
                self.saveButtonClicked)
        self.connect(self.closeButton, SIGNAL("clicked()"),\
                self.closeButtonClicked)
        self.connect(self.optionsButton, SIGNAL("clicked()"),\
                self.optionsButtonClicked)

        # Create table View        
        self.headers = ["Index", "-   Description   -",\
                "-   User   -", "-   Password   -",\
                "-   Last Updated   -", "-         Comments        -"]
        
        self.userTable.setColumnCount(len(self.headers))                        
        self.userTable.setSelectionBehavior(QTableWidget.SelectRows)
        self.userTable.setSelectionMode(QTableWidget.SingleSelection)
        
        # Hide table index column and show all other columns
        self.userTable.setColumnHidden(id_column_index, True)
        self.userTable.setColumnHidden(descr_column_index, False)
        self.userTable.setColumnHidden(user_column_index, False)
        self.userTable.setColumnHidden(passwd_column_index, False)
        self.userTable.setColumnHidden(comments_column_index, False)

        # Update table with records
        self.updateTableView()

        # Connect table widget to signal handlers
        self.connect(self.userTable,\
                SIGNAL("itemDoubleClicked(QTableWidgetItem*)"),\
                self.tableItemDoubleClicked)
        self.connect(self.userTable,\
                SIGNAL("itemSelectionChanged()"),\
                self.tableItemSelectionChanged)

    #---------------------------------------------------------------
    # Populate user list with user data
    #---------------------------------------------------------------

    def updateTableView(self):
        
        self.userTable.clear()

        # Retrieve records from database
        dbRecs = self.mySQLdb.listRecords(printStdOut=False)
        
        # Define column names
        self.userTable.setRowCount(len(dbRecs))        
        self.userTable.setHorizontalHeaderLabels(self.headers)
        self.userTable.resizeColumnsToContents()
        
        # Populate Table Widget rows with data from MySQL table        
        column_indexes = (id_column_index, descr_column_index,\
                user_column_index, passwd_column_index,\
                last_updated_column_index, comments_column_index)
        
        row_index = 0

        for row in dbRecs:
            
            for column_index in column_indexes:
                # Item to the table view
                item = QTableWidgetItem(str(row[column_index]))
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.userTable.setItem(row_index, column_index, item)

            row_index += 1

        if self.userTable.currentRow() < 0:
            self.userTable.selectRow(0)

        self.userTable.setFocus()

    #------------------------------------------------------------
    # Create Table View Item
    #------------------------------------------------------------

    def newTableViewItem(self) :

        newUserDlg = NewUserDialog(self)

        if newUserDlg.exec_() :

            # Get selected row index
            curRow = self.userTable.currentRow()
     
            # If exec_() returned 1 it means the user clicked OK button    
            newDescr = newUserDlg.getData()['descr']
            newUser = newUserDlg.getData()['user']
            newPasswd = newUserDlg.getData()['passwd']
            newComm = newUserDlg.getData()['comm']
        
            # Add user to database    
            self.mySQLdb.addRecord(descr=newDescr, user=newUser,\
                    passwd=newPasswd, comments=newComm,\
                    commit=False)

            if self.mySQLdb.getError():
                QMessageBox.critical(self, "Error", myQSLdb.getError())                 
            else:                      
                # Update table view with the new records
                self.updateTableView()
                self.userTable.selectRow(curRow)
        else:
            
            self.userTable.setFocus()
                 
    #------------------------------------------------------------
    # Delete Table View Item
    #------------------------------------------------------------

    def deleteTableViewItem(self):

        # Get selected row index
        curRow = self.userTable.currentRow()
        if curRow < 0:
            return

        selectedColumnId = self.userTable.item(curRow,\
                id_column_index).text()        

        # Remove record from database
        self.mySQLdb.removeRecord(index=selectedColumnId, commit = False)
 
        if self.mySQLdb.getError():
            QMessageBox.critical(self, "Error", myQSLdb.getError())                 
        else:                      
            # Update table view with the new records
            self.updateTableView() 

            if self.userTable.rowCount():                
                if curRow < self.userTable.rowCount() :
                    # Move on to the next row
                    self.userTable.selectRow(curRow)
                else:
                    # There is no next row, so move on
                    # to the previous row
                    self.userTable.selectRow(curRow - 1)                    
            else:
                # No more user records left, so disable Edit and Delete
                # buttons
                self.editButton.setEnabled(False)        
                self.deleteButton.setEnabled(False)             

    #--------------------------------------------------------------
    # Edit Table View item
    #--------------------------------------------------------------

    def editTableViewItem(self) :
        
        usrInfo = dict()

        curRow = self.userTable.currentRow()
        if curRow < 0:
            return

        usrInfo['column_id'] = self.userTable.item(curRow,\
                id_column_index).text()
        usrInfo['descr'] = self.userTable.item(curRow,\
                descr_column_index).text()
        usrInfo['user'] = self.userTable.item(curRow,\
                user_column_index).text()
        usrInfo['passwd'] = self.userTable.item(curRow,\
                passwd_column_index).text()
        usrInfo['comm'] = self.userTable.item(curRow,\
                comments_column_index).text()        
       
        editUserDlg = EditUserDialog(usrInfo)

        if editUserDlg.exec_() :

            # If exec_() returned 1 it means the user clicked OK
            # button
            newDescr = editUserDlg.getData()['descr']
            newUser = editUserDlg.getData()['user']
            newPasswd = editUserDlg.getData()['passwd']
            newComm = editUserDlg.getData()['comm']
                        
            self.mySQLdb.editRecord(index=usrInfo['column_id'],\
                    newDescr=newDescr, newUser=newUser,\
                    newPasswd=newPasswd, newComm=newComm, commit=False)

            if mySQLdb.getError():
                QMessageBox.critical(self, "Error", mySQLdb.getError())
            else:
                # Update table view with the new records
                self.updateTableView()

                # Re-select current row
                self.userTable.selectRow(curRow) 

        else:

            self.userTable.setFocus()

    #-------------------------------------------------------------
    # The user clicked New button
    #-------------------------------------------------------------

    def newButtonClicked(self):

        self.newTableViewItem()    

    #--------------------------------------------------------------
    # Override default key pressed event handler
    #--------------------------------------------------------------

    def keyPressEvent(self,event):

        QDialog.keyPressEvent(self,event)

        if event.key() == Qt.Key_Delete :
            self.deleteTableViewItem()

        if event.key() == Qt.Key_Return :
            self.editTableViewItem()

        if event.key() == Qt.Key_Insert :
            self.newTableViewItem()
       
    #--------------------------------------------------------------
    # The user clicked Edit button
    #--------------------------------------------------------------

    def editButtonClicked(self):
       
        self.editTableViewItem()
 
    #--------------------------------------------------------------
    # The user clicked Delete button
    #--------------------------------------------------------------

    def deleteButtonClicked(self):
        
        self.deleteTableViewItem()
 
    #--------------------------------------------------------------
    # The user clicked Save button
    #--------------------------------------------------------------

    def saveButtonClicked(self):

        self.mySQLdb.commit()
        mySQLdb.clearPendingChanges()

        QMessageBox.information(self, "Information",\
               "Users saved to database")

    #-------------------------------------------------------------
    # The user clicked Close button
    #-------------------------------------------------------------

    def closeButtonClicked(self):
        
        if mySQLdb.changesPending():
            reply = QMessageBox.warning(self, "Warning",\
                    "User database has been modified.\n\n" +\
                    "Would you like to save the changes?",\
                    QMessageBox.Yes | QMessageBox.No,\
                    QMessageBox.Yes)

            if reply == QMessageBox.Yes:                   
                self.mySQLdb.commit()
                self.mySQLdb.clearPendingChanges()

                QMessageBox.information(self, "Information",\
                       "Users saved to database")  
        
        self.close() 

    #-------------------------------------------------------------
    # The user clicked Options button
    #-------------------------------------------------------------

    def optionsButtonClicked(self):

        cfgFileEdit = cfgFile()

        # Read current settings from config file
        curCfg = cfgFileEdit.read(self.securityKey)

        # Display Options dialog
        editOptionsDlg = EditOptionsDialog(curCfg)

        if editOptionsDlg.exec_() :

            # If exec_() returned 1 it means the user clicked OK
            # button
            newUser = editOptionsDlg.getData()['mysqlUser']            
            newPasswd = editOptionsDlg.getData()['mysqlPasswd']
                    
            newCfg = dict(mysqlUser = newUser, mysqlPasswd = newPasswd)

            cfgFileEdit.update(newCfg, self.securityKey)
    
    #-------------------------------------------------------------
    # The user clicked on the table view, so we need to enable
    #  Edit and Delete
    #-------------------------------------------------------------

    def tableItemSelectionChanged(self):

        self.editButton.setEnabled(True)
        self.deleteButton.setEnabled(True)
  
    #-------------------------------------------------------------
    # The user double-clicked an element
    #-------------------------------------------------------------
       
    def tableItemDoubleClicked(self, item):
                
        self.editTableViewItem()

    #-------------------------------------------------------------
    # Show a warning on close if there are pending changes
    #-------------------------------------------------------------

    def closeEvent(self, event):

        if mySQLdb.changesPending():
            reply = QMessageBox.warning(self, "Warning",\
                    "User database has been modified.\n\n" +\
                    "Would you like to save the changes?",\
                    QMessageBox.Yes | QMessageBox.No,\
                    QMessageBox.Yes)

            if reply == QMessageBox.Yes:                   
                self.mySQLdb.commit()
                self.mySQLdb.clearPendingChanges()

                QMessageBox.information(self, "Information",\
                       "Users saved to database")  
        
        self.close()

######################################################################
#
# Define global variables here
#
######################################################################

dbName = "passwords"
dbTableName = "user_passwords"

id_column_index = 0
descr_column_index = 1
user_column_index = 2
passwd_column_index = 3
last_updated_column_index = 4
comments_column_index = 5

######################################################################
#
# Main loop starts here
#
######################################################################

user = ""
user_index = ""
descr = ""
comments = ""
passwd = ""

mode = "gui"
promptForSecurityKey = "True"

#---------------------------------------------------------------------
# Get username/password from cmd line
#----------------------------------------------------------------------

try:
    opts, args = getopt.getopt(sys.argv[1:],"arelu:p:s:d:i:c:",\
            ["add", "remove", "edit", "list", "user", "passwd",\
            "security", "description", "index", "comments"])
except:

    print ("""
        Usage:

        To add a new user:
             pwd_mgr     -a -u <user> -p <password> -d <description text>
                     [-c <comments>]
        To list users:
             pwd_mgr     -l

        To edit a user:
             pwd_mgr     -e -i <user index> [-u <user>] [-p <new password>]
                     [-d <new descr>] [-c <new comments>]

        To remove a user from database:
             pwd_mgr     -r -i <user index>

        To specify security key from cmd line add -s <key> option """)

    sys.exit(1)

for opt, arg in opts:
    
    if opt in ("-a", "--add"):
        if mode in ("remove", "list", "edit"):
            print ("Can't use 'add' with 'remove|list'")
            sys.exit(1)
        else:
            mode = "add"
    elif opt in ("-r", "--remove"):
        if mode in ("add", "list", "edit"):
            print("Can't use 'remove' with 'add|list|edit'")
            sys.exit(1)
        else:
            mode = "remove"
    elif opt in ("-e", "--edit"):
        if mode in ("add", "list", "remove"):
            print("Can't use 'edit' with 'add|list|remove'")
            sys.exit(1)
        else:
            mode = "edit"
    elif opt in ("-l", "--list"):
        if mode in ("add", "remove", "edit"):
            print("Can't use 'list' with 'add|remove|edit'")
            sys.exit(1)
        else:
            mode = "list"
    elif opt in ("-s", "--security"):
        securityKey = arg
        promptForSecurityKey = False

# Read username and description from cmd line
# Comments will be set to "" by default
if mode in "add":
    for opt, arg in opts:
        if opt in ("-u", "--user"):
            user = arg
        if opt in ("-d", "--description"):
            descr = arg
        if opt in ("-c", "--comments"):
            comments = arg
        if opt in ("-p", "--passwd"):
            passwd = arg

    if not user:
        print ("Must specify user when mode is 'add'")
        sys.exit(1)
    if not descr:
        print ("Must specify description when mode is 'add'")
        sys.exit(1)
    if not passwd:
        print ("Must specify password when mode is 'add'")
        sys.exit(1)

# Read record index from cmd line
if mode in ("remove"):
    for opt, arg in opts:
        if opt in ("-i", "--index"):
            user_index = arg

    if not user_index:
        print ("Must specify user index when mode is 'remove'")
        sys.exit(1)

# Read password from cmd line
if mode in ("edit"):
    for opt, arg in opts:
        if opt in ("-i", "--user_index"):
            user_index = arg
        if opt in ("-u", "--user"):
            user = arg
        if opt in ("-d", "--description"):
            descr = arg
        if opt in ("-c", "--comments"):
            comments = arg   
        if opt in ("-p", "--passwd"):
            passwd = arg

    if not user_index:
        print ("Must specify user index when mode is 'edit'")
        sys.exit(1)
        
    if not user + descr + comments + passwd:
        print ("Must specify at least one of the following -u, -d,"
                "-c, -p when mode is 'edit'")
        sys.exit(1)

#----------------------------------------------------------------------
# If configuration file exists, read MySQL user name and password from it,
# and, if not, ask the user to enter user name and password from cmd line
# Also, prompt the user for the security key
#----------------------------------------------------------------------

cfgFileEdit = cfgFile()

if not cfgFileEdit.exists():

    ## Configuration file has not been found, need to create a new one
    ######################################################################

    print("\nFirst time login\n===================\n")
    dbUser = raw_input("Enter MySQL database user name: ")
    dbPasswd = getpass.getpass(prompt = "Enter MySQL database password: ")
    dbPasswdConfirm = getpass.getpass(prompt = "Confirm MySQL database "
            "password: ")
    if dbPasswd != dbPasswdConfirm:
        print ("Passwords did not match")
        sys.exit(1)

    if promptForSecurityKey:
        securityKey = getpass.getpass(prompt = "Enter security key "
                "you want to use with this database: ")
        securityKeyConfirm = getpass.getpass(prompt = "Confirm security "
                "key: ")
        if securityKey != securityKeyConfirm:
            print ("Security keys did not match")
            sys.exit(1)

    if len(securityKey) > 8:
        print("Error: length of security key can't exceed 8. The length"
                "of the key you specified is " + len(securityKey))
        sys.exit(1)

    # Save the user/password entered in the configuration file,
    # so that we don't need to prompt on the next run
    cfgData = dict(mysqlUser = dbUser, mysqlPasswd = dbPasswd)
    cfgFileEdit.update(cfgData = cfgData, securityKey = securityKey)
else:

    ## Configuration file has been found. Read config info from the file
    ####################################################################

    if promptForSecurityKey:
        securityKey = getpass.getpass(prompt = "Enter Security Key:"
                "\n=====================\n")
    if len(securityKey) > 8:
        print("Error: length of security key can't exceed 8. The length"
                "of the key you specified is " + len(securityKey))
        sys.exit(1)
    
    cfgData = cfgFileEdit.read(securityKey = securityKey)
    dbUser = cfgData['mysqlUser']
    dbPasswd = cfgData['mysqlPasswd']

#---------------------------------------------------------------------
# Initialise MySQLdb
#--------------------------------------------------------------------

mySQLdb = MySQLPWDdb(dbName=dbName, dbTableName=dbTableName,\
        dbUser=dbUser, dbPasswd=dbPasswd, securityKey=securityKey)

#---------------------------------------------------------------------
# Connect to mySQLdb
#---------------------------------------------------------------------

mySQLdb.connect()

if mySQLdb.getError():

    access_denied_msg = "access denied for user"

    # Access denied error, make sure user specified the correct
    # MySQL username and password
    if access_denied_msg in mySQLdb.getError().lower():

        print("Access denied for user " + dbUser + ", make sure you "
                "specified the correct MySQL username and password\n" +
                mySQLdb.getError())
        del mySQLdb

        # Ask user to re-enter username and password
        dbUser = raw_input("Re-enter MySQL database user name: ")
        dbPasswd = getpass.getpass(prompt = "Re-enter MySQL database"
                "password: ")
        dbPasswdConfirm = getpass.getpass(prompt = "Confirm MySQL database"
                "password: ")
        if dbPasswd != dbPasswdConfirm:
            print ("Passwords did not match")
            sys.exit(1)

        # See if we can connect to MySQL now
        mySQLdb = MySQLPWDdb(dbName=dbName, dbTableName=dbTableName,\
                dbUser=dbUser, dbPasswd=dbPasswd, securityKey=securityKey)
        
        mySQLdb.connect()
      
        if mySQLdb.getError():
            # Still can't connect, terminate the script
            print("Error connecting to MySQL database:\n" +\
                    mySQLdb.getError())
            sys.exit(1)
        else:
            # Update the config file with the correct password
            cfgData = dict(mysqlUser = dbUser, mysqlPasswd = dbPasswd)
            cfgFileEdit.update(cfgData = cfgData, securityKey = securityKey)
    else: 
        print("Error connecting to MySQL database:\n" + mySQLdb.getError())
        sys.exit(1)

#---------------------------------------------------------------------
# Perform operation requested
#---------------------------------------------------------------------

if mode == "gui":

    # Launch the GUI
    app = QApplication(sys.argv)

    usrLstDlg = UserListDialog(mySQLdb = mySQLdb, securityKey = securityKey)    
    usrLstDlg.show()

    app.exec_()

elif mode == "add":

    # Add user to database    
    mySQLdb.addRecord(user=user, passwd=passwd, descr=descr,\
            comments=comments)
    if mySQLdb.getError():
        print ("Error adding " + user + " to the database:"\
                + mySQLdb.getError())
        sys.exit(1)
    else:
        print ("User " + user + " added to database successfully")
           
elif mode == "remove":

    # Delete user from database
    mySQLdb.removeRecord(index=user_index)

    if mySQLdb.getError():
        print ("Error deleting user # " + index + "from the database:"\
                + mySQLdb.getError())
        sys.exit(1)
    else:
       print ("User # " + index + " removed from the database")
         
elif mode == "edit":

    # Modify the user
    mySQLdb.editRecord(index=user_index, newPasswd=passwd)

    if mySQLdb.getError():
        print ("Error updating user # " + index + "with the new info: "\
                + newPasswd)
        sys.exit(1)
    else:
        print("User # " + user_index + " has been updated with the new\
                info")
 
elif mode == "list":

    # Print list of users to stdout
    mySQLdb.listRecords()

    if mySQLdb.getError() :
        print ("Error retrieving database records: " + mySQLdb.getError())
        sys.exit(1)

#------------------------------------------------------------------------
# remove mySQLdb
#-----------------------------------------------------------------------

del mySQLdb

