# encoding: utf-8
require 'set'
require 'logstash/filters/base'
require 'logstash/namespace'

class LogStash::Filters::SDS < LogStash::Filters::Base
    config_name 'SDS'

    public

    def register
        @re_msg = /(?:Stormshield Data Security Login|Identifiant Stormshield Data Security)\s?:\s(?<userFullName>.*[^(?:\s{2}|\r{2})])(?:\s{2}|\r{2}|(?:\\\\r){2})Description\s?:(?:\s|\r|\\\\r)?(?<description>[^"]*)/m
        @re_file = /(?:File|fichier|file)\s*'(?<File>.*)'/
        @re_folder = /(?:Folder|dossier|folder)\s*'(?<Folder>.*)'/
        @eventId_files_set = Set.new [
            # "L'utilisateur a chiffré avec succès le fichier '%2' en mode auto-déchiffrable."
            # "File '%2' has been successfully encrypted (auto-decrypt mode)."
            18_300,
            # "Le chiffrement du fichier '%2' en mode auto-déchiffrable a échoué."
            # "File '%2' encryption (auto-decrypt mode) has failed."
            18_301,
            # "File '%2' was successfully encrypted (SmartFILE? mode)."
            # "L'utilisateur a chiffré avec succès le fichier '%2' en utilisant SecurityBOX? SmartFile?."
            18_304,
            # "File '%2' encryption (SmartFILE? mode) has failed."
            # "Le chiffrement du fichier '%2' en utilisant SecurityBOX? SmartFile? a échoué."
            18_305,
            # "L'utilisateur a chiffré avec succès le fichier '%2' pour les correspondants suivants : %r%3."
            # "File '%2' has been successfully encrypted for the following recipients: %r%3."
            18_308,
            # "File '%2' encryption has failed for the following recipients: %r%3."
            # "Le chiffrement du fichier '%2' pour les correspondants suivants a échoué : %r%3."
            18_309,
            # "Les collaborateurs suivants ont été ajoutés avec succès au fichier '%2' :%r%3."
            # "These coworkers have been added successfully to the file '%2' :%r%3."
            18_312,
            # "These coworkers could not be added to the file '%2' : %r%3."
            # "L'ajout des collaborateurs suivants au fichier '%2' a échoué :%r%3."
            18_313,
            # "Les collaborateurs suivants ont été supprimés avec succès du fichier '%2' :%r%3."
            # "These coworkers have been removed successfully from the file '%2':%r%3."
            18_314,
            # "La suppression des collaborateurs suivants du fichier '%2' a échoué : %r%3."
            # "These coworkers could not be removed from the file '%2': %r%3."
            18_315,
            # "L'utilisateur a chiffré le fichier '%2' avec succès."
            # "File '%2' has been successfully encrypted."
            18_700,
            # "Le chiffrement du fichier '%2' a échoué."
            # "File '%2' encryption has failed."
            18_701,
            # "L'utilisateur a déchiffré le fichier '%2' avec succès."
            # "File '%2' has been successfully decrypted."
            18_702,
            # "Le déchiffrement du fichier '%2' a échoué."
            # "File '%2' decryption has failed."
            18_703
        ]

        @eventId_folders_set = Set.new [
            # "L'utilisateur a chiffré avec succès le dossier '%2' en mode auto-déchiffrable."
            # "Folder '%2' has been successfully encrypted (auto-decrypt mode)."
            18_302,
            # "Le chiffrement du dossier '%2' en mode auto-déchiffrable a échoué."
            # "Folder '%2' decryption (auto-decrypt mode) has failed."
            18_303,
            # "Folder '%2' has been successfully encrypted (SmartFILE? mode)."
            # "L'utilisateur a chiffré avec succès le dossier '%2' en utilisant SecurityBOX? SmartFile?."
            18_306,
            # "Folder '%2' encryption (SmartFILE? mode) failed."
            # "Le chiffrement du dossier '%2' en utilisant SecurityBOX? SmartFile? a échoué."
            18_307,
            # "L'utilisateur a chiffré avec succès le dossier '%2' pour les correspondants suivants : %r%3."
            # "Folder '%2' has been successfully encrypted for the following recipients: %r%3."
            18_310,
            # "Le chiffrement du dossier '%2' pour les correspondants suivants a échoué: %r%3."
            # "Folder '%2' encryption has failed for the following recipients: %r%3."
            18_311
        ]
    end # def register

    public

    def filter(event)
        eventId = event.get('EventID')
        # Try to extract the header/description
        m = @re_msg.match(event.get('Message'))
        if m
            event.set('userFullName', m['userFullName'])
            event.set('msg', m['description'])
            event.remove('Message')
        end

        # Assign category name in EN function of event id range
        if eventId
            eventId = eventId.to_i
            case eventId
            when 300..699 then event.set('Category', 'Administration')
            when 700..1099 then event.set('Category', 'Directory administration')
            when 1100..1499  then event.set('Category', 'CRL administration')
            when 8300..8699  then event.set('Category', 'Volume management')
            when 18_300..18_699 then event.set('Category', 'Encryption / Decryption to')
            when 18_700..19_099 then event.set('Category', 'Encryption / Decryption')
            when 25_300..25_699 then event.set('Category', 'Start / Stop')
            when 25_700..26_099 then event.set('Category', 'Network')
            when 26_100..26_499 then event.set('Category', 'Card Extension')
            when 31_300..31_699 then event.set('Category', 'Login / Logout')
            when 31_700..32_099 then event.set('Category', 'Account administration')
            when 32_100..32_499 then event.set('Category', 'Key management')
            when 32_500..32_899 then event.set('Category', 'Keystore administration')
            when 39_300..39_699 then event.set('Category', 'Send / Receive')
            when 47_300..47_499 then event.set('Category', 'Sign / Signature')
            when 49_300..49_699 then event.set('Category', 'Rule management')
            when 49_700..50_099 then event.set('Category', 'Encryption / Decryption')
            when 50_100..50_499 then event.set('Category', 'Backup / Restore')
            when 50_500..50_899 then event.set('Category', 'Driver message')
            else
                event.set('Category', "Umanaged category: '" + event.get('Category') + "'")
            end

            # Capture file or folder name for file events
            m = nil
            if @eventId_files_set.include?(eventId)
                m = @re_file.match(event.get('msg'))
                if m
                  event.set('file', m['File'])
                end
            elsif @eventId_folders_set.include?(eventId)
                m = @re_folder.match(event.get('msg'))
                if m
                  event.set('folder', m['Folder'])
                end
            end
        end

        # filter_matched should go in the last line of our successful code
        filter_matched(event)
    end # def filter
end # class LogStash::Filters::SDS
