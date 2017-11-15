# encoding: utf-8

require 'logstash/devutils/rspec/spec_helper'
require 'logstash/filters/SDS'

describe LogStash::Filters::SDS do
    describe 'SDS log analyser' do
        unmanagedCategory = 'an unmanaged category'
        let(:config) do
            <<-CONFIG
      filter {
        SDS {
        }
      }
    CONFIG
        end

        # Test re_msg
        [
          {
            'message' => "Message=\"Stormshield Data Security Login: Amelia\r\rDescription:\rCOMMON_NAME_REVOKE option: Value: ALL Access FALSE",
            'expectedUserFullName' => 'Amelia',
            'expectedMsg' => 'COMMON_NAME_REVOKE option: Value: ALL Access FALSE'
          },
          {
            'message' => "Message=\"Stormshield Data Security Login: Emily\r\rDescription:\rThe Stormshield Data Security account or card is blocked.\" Category=\"Login / Logout\" Opcode=ERROR EventReceivedTime=1458835949 SourceModuleName=SDS_events SourceModuleType=im_msvistalog",
            'expectedUserFullName' => 'Emily',
            'expectedMsg' => 'The Stormshield Data Security account or card is blocked.'
          },
          {
            'message' => "Message=\"Identifiant Stormshield Data Security : Emily\r\rDescription :\rThe Stormshield Data Security account or card is blocked.\" Category=\"Login / Logout\" Opcode=ERROR EventReceivedTime=1458835949 SourceModuleName=SDS_events SourceModuleType=im_msvistalog",
            'expectedUserFullName' => 'Emily',
            'expectedMsg' => 'The Stormshield Data Security account or card is blocked.'
          },
          {
            'message' => "Stormshield Data Security Login: Bruno THILL\r\rDescription:\rUpdate of the CRL C:\\ProgramData\\Arkoon\\Security BOX\\Users\\bruno thill\\bruno thill.bcrl has been successful.",
            'expectedUserFullName' => 'Bruno THILL',
            'expectedMsg' => 'Update of the CRL C:\\ProgramData\\Arkoon\\Security BOX\\Users\\bruno thill\\bruno thill.bcrl has been successful.'
          },
          {
            'message' => "Stormshield Data Security Login: Bruno THILL\r\rDescription:\rDownload of the security policy from 'http://sbam.arkoon.net/update-users-fr/Bruno%20THILL/Bruno%20THILL.usx'.",
            'expectedUserFullName' => 'Bruno THILL',
            'expectedMsg' => "Download of the security policy from 'http://sbam.arkoon.net/update-users-fr/Bruno%20THILL/Bruno%20THILL.usx'."
          },
          {
            'message' => "Stormshield Data Security Login: THILL Bruno\r\rDescription:\rError while trying to open the file 'E:\\USERS\\BTHILL\\DOCUMENTS\\TESTS VERSION 9.1\\屜尯CARACTÈRES UNICODE - UTF-16 - あいおと - NOMS LONGS TEAM 8.0.6\\尯屜あいお尯あうおあい - COPIE - COPI - COPIE (68).DOC' using 'SBKRNL.EXE'.",
            'expectedUserFullName' => 'THILL Bruno',
            'expectedMsg' => "Error while trying to open the file 'E:\\USERS\\BTHILL\\DOCUMENTS\\TESTS VERSION 9.1\\屜尯CARACTÈRES UNICODE - UTF-16 - あいおと - NOMS LONGS TEAM 8.0.6\\尯屜あいお尯あうおあい - COPIE - COPI - COPIE (68).DOC' using 'SBKRNL.EXE'."
          },
          {
            'message' => "Stormshield Data Security Login: N/A\r\rDescription:\rCOMMON_NAME_REVOKE option: Value: ALL Access FALSE",
            'expectedUserFullName' => 'N/A',
            'expectedMsg' => 'COMMON_NAME_REVOKE option: Value: ALL Access FALSE'
          },
          {
            'message' => "Stormshield Data Security Login: N/A\r\rDescription:%COMMON_NAME_NOT_ON_LDAP option: Value: ALL Access FALSE",
            'expectedUserFullName' => 'N/A',
            'expectedMsg' => '%COMMON_NAME_NOT_ON_LDAP option: Value: ALL Access FALSE'
          },
          {
            'message' => "Stormshield Data Security Login: Bruno THILL\r\rDescription:\rThe user logged out its Stormshield Data Security keystore.",
            'expectedUserFullName' => 'Bruno THILL',
            'expectedMsg' => 'The user logged out its Stormshield Data Security keystore.'
          },
          {
            'message' => "Stormshield Data Security Login: Bruno THILL\r\rDescription:\rThe user logged on its Stormshield Data Security keystore.",
            'expectedUserFullName' => 'Bruno THILL',
            'expectedMsg' => 'The user logged on its Stormshield Data Security keystore.'
          },
          {
            'message' => "Stormshield Data Security Login: THILL Bruno\r\rDescription:\rTeam service request failed: 'C:\\TMP\\TESTTEST\\CHALLENGE.DOCX.SBCLOUD|TEAMOFB (4)' using 'explorer.exe'.",
            'expectedUserFullName' => 'THILL Bruno',
            'expectedMsg' => "Team service request failed: 'C:\\TMP\\TESTTEST\\CHALLENGE.DOCX.SBCLOUD|TEAMOFB (4)' using 'explorer.exe'."
          },
          {
            'message' => "Stormshield Data Security Login: THILL Bruno\r\rDescription:\rAutomatic volume mounting'E:\\Users\\bthill\\Documents\\Tests Version 9.1\\9.1.vbox' has been successfully operated on 'Z:\\' in 'RW' mode.",
            'expectedUserFullName' => 'THILL Bruno',
            'expectedMsg' => "Automatic volume mounting'E:\\Users\\bthill\\Documents\\Tests Version 9.1\\9.1.vbox' has been successfully operated on 'Z:\\' in 'RW' mode."
          },
          {
            'message' => "Identifiant Stormshield Data Security : Jocelyn KRYSTLIK\r\rDescription :\rLe déverrouillage de la session Stormshield Data Security de l'utilisateur s'est déroulé normalement.",
            'expectedUserFullName' => 'Jocelyn KRYSTLIK',
            'expectedMsg' => "Le déverrouillage de la session Stormshield Data Security de l'utilisateur s'est déroulé normalement."
          },
          {
            'message' => "Identifiant Stormshield Data Security : Jocelyn KRYSTLIK  Description : La demande au service Team a échoué : ''\\\\ARKOON.NET\\BAOBAB\\SHARE\\JPC\\SECURED\\SBOXTEAM.SBT|TEAMOFB (7)'' par ''SBKRNL.EXE''.",
            'expectedUserFullName' => 'Jocelyn KRYSTLIK',
            'expectedMsg' => "La demande au service Team a échoué : ''\\\\ARKOON.NET\\BAOBAB\\SHARE\\JPC\\SECURED\\SBOXTEAM.SBT|TEAMOFB (7)'' par ''SBKRNL.EXE''."
          },
          {
            'message' => "Stormshield Data Security Login: Oscar\\\\r\\\\rDescription:\\\\rRépertoire d'installation : C:\\Program Files\\Arkoon\\Security BOX",
            'expectedUserFullName' => 'Oscar',
            'expectedMsg' => "Répertoire d'installation : C:\\Program Files\\Arkoon\\Security BOX"
          },
        ].each do |test|
            sample('Message' => test['message']) do
                expect(subject.get('userFullName')).to eq(test['expectedUserFullName'])
                expect(subject.get('msg')).to eq test['expectedMsg']
            end
        end

        # Test that category is well replaced by EN value
        sample(
            'Category' => 'Installation de la Suite Stormshield Data Security',
            'EventID' => '301',
        ) do
            expect(subject.get('Category')).to eq('Administration')
        end

        # Test a full syslog message
        sample('Message' => "id=datasecurity AccountName=\"Amelia\" AccountType=User Category=\"Directory administration\" Channel=\"Stormshield Data Security\" Domain=domain.local EventID=728 EventReceivedTime=1471940690 EventTime=\"2016-08-23 08:24:50\" EventType=INFO HostIP=\"10.0.100.11\" Hostname=\"pc11\" Keywords=36028797018963968 Message=\"Stormshield Data Security Login: Amelia\r\rDescription:\rCOMMON_NAME_REVOKE option: Value: ALL Access FALSE\" Opcode=Informations ProcessID=0 RecordNumber=541 Severity=INFO SeverityValue=2 SourceModuleName=SDS_events SourceModuleType=im_msvistalog SourceName=\"Administration\" Task=6 ThreadID=0 UserID=S-1-5-21-1986321934-3787518990-59020978-1000\"") do
            expect(subject.get('userFullName')).to eq('Amelia')
            expect(subject.get('msg')).to eq 'COMMON_NAME_REVOKE option: Value: ALL Access FALSE'
        end

        # Test categories from event id
        {
          "300" => "Administration",
          "699'" => "Administration",
          "700'" => "Directory administration",
          "1099'" => "Directory administration",
          "1100'" => "CRL administration",
          "1499'" => "CRL administration",
          "8300'" => "Volume management",
          "8699'" => "Volume management",
          "18300" => "Encryption / Decryption to",
          "18699" => "Encryption / Decryption to",
          "18700" => "Encryption / Decryption",
          "19099" => "Encryption / Decryption",
          "25300" => "Start / Stop",
          "25699" => "Start / Stop",
          "25700" => "Network",
          "26099" => "Network",
          "26100" => "Card Extension",
          "26499" => "Card Extension",
          "31300" => "Login / Logout",
          "31699" => "Login / Logout",
          "31700" => "Account administration",
          "32099" => "Account administration",
          "32100" => "Key management",
          "32499" => "Key management",
          "32500" => "Keystore administration",
          "32899" => "Keystore administration",
          "39300" => "Send / Receive",
          "39699" => "Send / Receive",
          "47300" => "Sign / Signature",
          "47499" => "Sign / Signature",
          "49300" => "Rule management",
          "49699" => "Rule management",
          "49700" => "Encryption / Decryption",
          "50099" => "Encryption / Decryption",
          "50100" => "Backup / Restore",
          "50499" => "Backup / Restore",
          "50500" => "Driver message",
          "50899" => "Driver message"
        }.each do |eventID, category|
          sample('EventID' => eventID) do
              expect(subject.get('Category')).to eq(category)
          end
        end

        # Test unmamaged category
        sample('EventID' => '50900', 'Category' => unmanagedCategory) do
          expect(subject.get('Category')).to eq("Umanaged category: '" + unmanagedCategory + "'")
        end

        # Test file events
        {
          "18703" => "File 'A fake file' decryption has failed.",
          "18301" => "File 'A fake file' encryption (auto-decrypt mode) has failed.",
          "18305" => "File 'A fake file' encryption (SmartFILE? mode) has failed.",
          "18309" => "File 'A fake file' encryption has failed for the following recipients: %r%3.",
          "18701" => "File 'A fake file' encryption has failed.",
          "18702" => "File 'A fake file' has been successfully decrypted.",
          "18300" => "File 'A fake file' has been successfully encrypted (auto-decrypt mode).",
          "18308" => "File 'A fake file' has been successfully encrypted for the following recipients: %r%3.",
          "18700" => "File 'A fake file' has been successfully encrypted.",
          "18304" => "File 'A fake file' was successfully encrypted (SmartFILE? mode).",
          "18303" => "Folder 'A fake file' decryption (auto-decrypt mode) has failed.",
          "18307" => "Folder 'A fake file' encryption (SmartFILE? mode) failed.",
          "18311" => "Folder 'A fake file' encryption has failed for the following recipients: %r%3.",
          "18302" => "Folder 'A fake file' has been successfully encrypted (auto-decrypt mode).",
          "18306" => "Folder 'A fake file' has been successfully encrypted (SmartFILE? mode).",
          "18310" => "Folder 'A fake file' has been successfully encrypted for the following recipients: %r%3.",
          "18313" => "L'ajout des collaborateurs suivants au fichier 'A fake file' a échoué :%r%3.",
          "18302" => "L'utilisateur a chiffré avec succès le dossier 'A fake file' en mode auto-déchiffrable.",
          "18306" => "L'utilisateur a chiffré avec succès le dossier 'A fake file' en utilisant SecurityBOX? SmartFile?.",
          "18310" => "L'utilisateur a chiffré avec succès le dossier 'A fake file' pour les correspondants suivants : %r%3.",
          "18300" => "L'utilisateur a chiffré avec succès le fichier 'A fake file' en mode auto-déchiffrable.",
          "18304" => "L'utilisateur a chiffré avec succès le fichier 'A fake file' en utilisant SecurityBOX? SmartFile?.",
          "18308" => "L'utilisateur a chiffré avec succès le fichier 'A fake file' pour les correspondants suivants : %r%3.",
          "18700" => "L'utilisateur a chiffré le fichier 'A fake file' avec succès.",
          "18702" => "L'utilisateur a déchiffré le fichier 'A fake file' avec succès.",
          "18315" => "La suppression des collaborateurs suivants du fichier 'A fake file' a échoué : %r%3.",
          "18303" => "Le chiffrement du dossier 'A fake file' en mode auto-déchiffrable a échoué.",
          "18307" => "Le chiffrement du dossier 'A fake file' en utilisant SecurityBOX? SmartFile? a échoué.",
          "18311" => "Le chiffrement du dossier 'A fake file' pour les correspondants suivants a échoué: %r%3.",
          "18701" => "Le chiffrement du fichier 'A fake file' a échoué.",
          "18301" => "Le chiffrement du fichier 'A fake file' en mode auto-déchiffrable a échoué.",
          "18305" => "Le chiffrement du fichier 'A fake file' en utilisant SecurityBOX? SmartFile? a échoué.",
          "18309" => "Le chiffrement du fichier 'A fake file' pour les correspondants suivants a échoué : %r%3.",
          "18703" => "Le déchiffrement du fichier 'A fake file' a échoué.",
          "18312" => "Les collaborateurs suivants ont été ajoutés avec succès au fichier 'A fake file' :%r%3.",
          "18314" => "Les collaborateurs suivants ont été supprimés avec succès du fichier 'A fake file' :%r%3.",
          "18313" => "These coworkers could not be added to the file 'A fake file' : %r%3.",
          "18315" => "These coworkers could not be removed from the file 'A fake file': %r%3.",
          "18312" => "These coworkers have been added successfully to the file 'A fake file' :%r%3.",
          "18314" => "These coworkers have been removed successfully from the file 'A fake file':%r%3.",
        }.each do |eventID, message|
          sample('EventID' => eventID, 'Message' => "Stormshield Data Security Login: A fake login\r\rDescription:\r" + message) do
              expect(subject.get('file')).to eq('A fake file')
          end
        end

    end
end
