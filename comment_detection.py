from base64 import b85decode as b64decode
from confusables import confusable_regex, normalize
import re
import os
import Scripts.files as files
from pkg_resources import parse_version
import json
import ast
import unicodedata
import Scripts.utils as utils
import itertools

RESOURCES_FOLDER_NAME = "SpamPurge_Resources"


######################### Convert string to set of characters#########################
def make_char_set(stringInput, stripLettersNumbers=False, stripKeyboardSpecialChars=False, stripPunctuation=False):
    # Optional lists of characters to strip from string
    translateDict = {}
    charsToStrip = " "
    if stripLettersNumbers == True:
      numbersLettersChars = ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
      charsToStrip += numbersLettersChars
    if stripKeyboardSpecialChars == True:
      keyboardSpecialChars = ("!@#$%^&*()_+-=[]\{\}|;':,./<>?`~")
      charsToStrip += keyboardSpecialChars
    if stripPunctuation == True:
      punctuationChars = ("!?\".,;:'-/()")
      charsToStrip += punctuationChars
    
    # Adds characters to dictionary to use with translate to remove these characters
    for c in charsToStrip:
      translateDict[ord(c)] = None
    translateDict[ord("\ufe0f")] = None # Strips invisible varation selector for emojis
    
    # Removes charsToStrip from string
    stringInput = stringInput.translate(translateDict)
    listedInput = list(stringInput)
    
    return set(filter(None, listedInput))

resourceFolder = RESOURCES_FOLDER_NAME
whitelistPathWithName = os.path.join(resourceFolder, "whitelist.txt")
spamListFolder = os.path.join(resourceFolder, "Spam_Lists")
spamListDict = {
    'Lists': {
      'Domains':  {'FileName': "SpamDomainsList.txt"},
      'Accounts': {'FileName': "SpamAccountsList.txt"},
      'Threads':  {'FileName': "SpamThreadsList.txt"}
    },
    'Meta': {
      'VersionInfo': {'FileName': "SpamVersionInfo.json"},
      'SpamListFolder': spamListFolder
      #'LatestLocalVersion': {}
    }
}
resourcesDict = {
  'Whitelist': {
    'PathWithName': whitelistPathWithName,
    'FileName': "whitelist.txt",
  }
}

if not os.path.isdir(resourceFolder):
    try:
      os.mkdir(resourceFolder)
      # Create readme
      with open(os.path.join(resourceFolder, "_What_Is_This_Folder.txt"), "w") as f:
        f.write("# This Resources folder is used to store resources required for the YT Spammer Purge program.\n")
        f.write("# Note: If you had a previous spam_lists folder that was created in the same folder as \n")
        f.write("# the .exe file, you can delete that old spam_lists folder. The resources folder is the \n")
        f.write("# new location they will be stored.\n")
                
    except:
      print("\nError: Could not create folder. To update the spam lists, try creating a folder called 'SpamPurge_Resources',")
      print("       then inside that, create another folder called 'Spam_Lists'.")

if os.path.isdir(resourceFolder) and not os.path.isdir(spamListFolder):
    try:
        os.mkdir(spamListFolder)
    except:
        print("\nError: Could not create folder. To update the spam lists, go into the 'SpamPurge_Resources' folder,")
        print("       then inside that, create another folder called 'Spam_Lists'.")

for x,spamList in spamListDict['Lists'].items():
    spamList['Path'] = os.path.join(spamListFolder, spamList['FileName'])
spamListDict['Meta']['VersionInfo']['Path'] = os.path.join(spamListFolder, spamListDict['Meta']['VersionInfo']['FileName']) # Path to version included in packaged assets folder

latestLocalSpamListVersion = "1900.12.31"
for x, spamList in spamListDict['Lists'].items():
    if not os.path.exists(spamList['Path']):
        files.copy_asset_file(spamList['FileName'], spamList['Path'])

listVersion = files.get_list_file_version(spamList['Path'])
spamList['Version'] = listVersion
if parse_version(listVersion) > parse_version(latestLocalSpamListVersion):
  latestLocalSpamListVersion = listVersion

spamListDict['Meta']['VersionInfo']['LatestLocalVersion'] = latestLocalSpamListVersion

if not os.path.exists(spamListDict['Meta']['VersionInfo']['Path']):
    files.copy_asset_file(spamListDict['Meta']['VersionInfo']['FileName'], spamListDict['Meta']['VersionInfo']['Path'])

jsonData = open(spamListDict['Meta']['VersionInfo']['Path'], 'r', encoding="utf-8")
versionInfoJson = str(json.load(jsonData)) # Parses json file into a string
versionInfo = ast.literal_eval(versionInfoJson) # Parses json string into a dictionary
spamListDict['Meta']['VersionInfo']['LatestRelease'] = versionInfo['LatestRelease']
spamListDict['Meta']['VersionInfo']['LastChecked'] = versionInfo['LastChecked']

for x, spamList in spamListDict['Lists'].items():
    spamList['FilterContents'] = files.ingest_list_file(spamList['Path'], keepCase=False)

#########################################################################################################
sensitive = False
spamLists = {}
rootDomainsList = []

rootDomainListAssetFile = "rootZoneDomainList.txt"
rootDomainList = files.ingest_asset_file(rootDomainListAssetFile)
resources = rootDomainList
spamLists['spamDomainsList'] = spamListDict['Lists']['Domains']['FilterContents']
spamLists['spamAccountsList'] = spamListDict['Lists']['Accounts']['FilterContents']
spamLists['spamThreadsList'] = spamListDict['Lists']['Threads']['FilterContents']
resources = resourcesDict

rootDomainList = rootDomainsList
spamDomainsList = spamLists['spamDomainsList'] # List of domains from crowd sourced list
spamThreadsList = spamLists['spamThreadsList'] # List of filters associated with spam threads from crowd sourced list
spamAccountsList = spamLists['spamAccountsList'] # List of mentioned instagram/telegram scam accounts from crowd sourced list

utf_16 = "utf-8"

blackAdWords, redAdWords, yellowAdWords, exactRedAdWords, = [], [], [], []
usernameBlackWords, usernameNovidBlackWords, usernameObfuBlackWords, textExactBlackWords, textUpLowBlackWords = [], [], [], [], []
compiledRegexDict = {
  'usernameBlackWords': [],
  'usernameNovidBlackWords': [],
  'blackAdWords': [],
  'redAdWords': [],
  'yellowAdWords': [],
  'exactRedAdWords': [],
  'usernameRedWords': [],
  'textObfuBlackWords': [],
  'usernameObfuBlackWords': [],
  'textExactBlackWords': [],
  'textUpLowBlackWords': [],
}

# General Spammer Criteria
#usernameBlackChars = ""
spamGenEmoji_Raw = b'@Sl-~@Sl-};+UQApOJ|0pOJ~;q_yw3kMN(AyyC2e@3@cRnVj&SlB@'
usernameBlackWords_Raw = [b'aA|ICWn^M`', b'aA|ICWn>^?c>', b'Z*CxTWo%_<a$#)', b'c4=WCbY*O1XL4a}', b'Z*CxIZgX^DXL4a}', b'Z*CxIX8', b'V`yb#YanfTAY*7@', b'b7f^9ZFwMLXkh', b'c4>2IbRcbcAY*7@', b'cWHEJATS_yX=D', b'cWHEJAZ~9Uc4=e', b'cWHEJZ*_DaVQzUKc4=e', b'X>N0LVP|q-Z8`', b'Z*CxIZgX^D', b'Z*CxIZgX^DAZK!6Z2', b'c4=WCX>N0LVP|q-Z2', b'b9G`gb9G_', b'b9G`MG$3<zVg']
usernameNovidBlackWords_Raw = [b'cWHEJATS_yX=D', b'cWHEJAZ~9Uc4=e', b'cWHEJZ*_DaVQzUKc4=e']
usernameObfuBlackWords_Raw = [b'c4Bp7YjX', b'b|7MPV{3B']
usernameRedWords = ["whatsapp", "telegram"]
textObfuBlackWords = ['telegram']
textExactBlackWords_Raw = [b'Z*6BRAZ2)AV{~kJAa`hCbRcOUZe?X;Wn=', b'Z*6BRAZ2)AV{~kJAa`hCbRc<ebs%nKWn^V!', b'Z*6BRAZ2)AV{~kJAa`hCbRckLZ*Xj7AZ}%4WMyO', b'ZDnU+ZaN?$Xm50MWpW|']
textUpLowBlackWords_Raw = [b'O<5pAPfk=tPE;UCQv', b'Ngz!@OGO}8L0KR|MO0KpQXoT5PE<usQ~', b'O<5pTNkm0YQy@W7MF']

# General Settings
unicodeCategoriesStrip = ["Mn", "Cc", "Cf", "Cs", "Co", "Cn"] # Categories of unicode characters to strip during normalization
lowAl = b'VPa!sWoBn+X=-b1ZEkOHadLBXb#`}nd3p'

# Create General Lists
spamGenEmojiSet = make_char_set(b64decode(spamGenEmoji_Raw).decode(utf_16))
lowAlSet = make_char_set(b64decode(lowAl).decode(utf_16))
  #usernameBlackCharsSet = make_char_set(usernameBlackChars)
for x in usernameBlackWords_Raw: usernameBlackWords.append(b64decode(x).decode(utf_16))
for x in usernameNovidBlackWords_Raw: usernameNovidBlackWords.append(b64decode(x).decode(utf_16))
for x in usernameObfuBlackWords_Raw: usernameObfuBlackWords.append(b64decode(x).decode(utf_16))
for x in textExactBlackWords_Raw: textExactBlackWords.append(b64decode(x).decode(utf_16))
for x in textUpLowBlackWords_Raw: textUpLowBlackWords.append(b64decode(x).decode(utf_16))

# Type 1 Spammer Criteria
minNumbersMatchCount = 6 # Choice of minimum number of matches from spamNums before considered spam
spamNums = b'@4S%jypiv`lJC5e@4S@nyp`{~mhZfm@4T4ryqWL3kng;a@4S-lyp!*|l<&Ni@4S}pyqE91nD4xq-+|(hpyH9V;*yBsleOZVw&I?E;+~4|pM-+ovAy7_sN#{K;*quDl8NGzw&I<);+}!xo{R9GgoEI*sp65M;*qxEl8WM!x8j|+;+}%yo{aFHgoNO$sp65N;*q!Fl8fS#xZ<6;;+})zo{jLIgoWafq~ejd;*yNwleyxZy5gRM;+~G;o`m9_j_{v^hT@T>;*q)Hl8xe%y5gO?;+}=#o{#XKgoomhrs9#h;*yTyle^-byyBjQ;+~N3k%YbQpM;3vf|%lwr{a;j;*yWzlf2@cz2csS;+~Q4pM;6xk*MO4yyB9O;*-7Noxb9ph~l1-@SlW=;*+Z4lfUqvgp2T>gpBZ?gn{s%gn;m!pN{aIpP2BSpQ7-cpRDkmpO5gJpPBHTpRMqnpQG@dpSJLwpOEmKpPKNUpRVwopQP}epSSRxpONsLpPTTVpRe$ppQZ4fpSbXypOWyMpPcZWpRn+qpQiAgpSkdzpOf&NpPlfXpRw?rpQrGhpStj!pOo;OpPulYpR(|spQ!MipS$p#pOx^PpP%rZpR@3tpQ-SjpS<v$pO)~QpP=xapS19upQ`YkpS|#%pO^5RpP}%bpSAFvpR4elpT6*&pT7'
spamPlus = b';+&e|oSEXDmBO*hmf?`8;(@y2f{NmZlj4Y!;)<2xik{-1wBo0_;-|afsDa|BgyN{8;;5tIsHEbkrQ)cj;;5(MsHozot>UPz;;6aesj=dzvf`|=@42Gyyo=$Rt>S^4;+U!8n5g2IrsA2f;+e7Ho2cTPnc|$9;+&h}oSfpEo#LFH;+&u2oS^EOn(CUH@Sl}{@Sl}|@Sl}}@Sl~2@Sl~3@Sl~4@SmQc@SmQd@SmQe@SmQf@SmQg@SmQh@SmQi'
spamOne = b'@4S)lou7~Jou8TTou8xdou94nou9Yjl8EAywc?$&;+}xwo{I3Fgo59J;*p@@k+c'
x = b64decode(spamNums).decode(utf_16)
y = b64decode(spamPlus).decode(utf_16)
z = b64decode(spamOne).decode(utf_16)

# Prepare Filters for Type 1 Spammers
spammerNumbersSet = make_char_set(x)
regexTest1 = f"[{y}] ?[1]"
regexTest2 = f"[+] ?[{z}]"
regexTest3 = f"[{y}] ?[{z}]"
compiledNumRegex = re.compile(f"({regexTest1}|{regexTest2}|{regexTest3})")

# Type 2 Spammer Criteria
blackAdWords_Raw = [b'V`yb#YanfTAaHVTW@&5', b'Z*XO9AZ>XdaB^>EX>0', b'b7f^9ZFwMYa&Km7Yy', b'V`yb#YanfTAa-eFWp4', b'V`yb#YanoPZ)Rz1', b'V`yb#Yan)MWMyv', b'bYXBHZ*CxMc>', b'Z*CxMc_46UV{~<LWd']
redAdWords_Raw = [b'W_4q0', b'b7gn', b'WNBk-', b'WFcc~', b'W-4QA', b'W-2OUYX', b'Zgpg3', b'b1HZ', b'F*qv', b'aBp&M']
yellowAdWords_Raw = [b'Y;SgD', b'Vr5}<bZKUFYy', b'VsB)5', b'XK8Y5a{', b'O~a&QV`yb=', b'Xk}@`pJf', b'Xm4}']
exactRedAdWords_Raw = [b'EiElAEiElAEiElAEiElAEiElAEiElAEiElAEiElAEiElAEiElAEiC', b'Wq4s@bZmJbcW7aBAZZ|OWo2Y#WB']
redAdEmoji = b64decode(b'@Sl{P').decode(utf_16)
yellowAdEmoji = b64decode(b'@Sl-|@Sm8N@Sm8C@Sl>4@Sl;H@Sly0').decode(utf_16)
hrt = b64decode(b';+duJpOTpHpOTjFpOTmGpOTaCpOTsIpOTvJpOTyKpOT#LpQoYlpOT&MpO&QJouu%el9lkElAZ').decode(utf_16)

# Create Type 2 Lists
for x in blackAdWords_Raw: blackAdWords.append(b64decode(x).decode(utf_16))
for x in redAdWords_Raw: redAdWords.append(b64decode(x).decode(utf_16))
for x in yellowAdWords_Raw: yellowAdWords.append(b64decode(x).decode(utf_16))
for x in exactRedAdWords_Raw: exactRedAdWords.append(b64decode(x).decode(utf_16))

# Prepare Filters for Type 2 Spammers
redAdEmojiSet = make_char_set(redAdEmoji)
yellowAdEmojiSet = make_char_set(yellowAdEmoji)
hrtSet = make_char_set(hrt)

# Prepare Regex to detect nothing but video link in comment
onlyVideoLinkRegex = re.compile(r"^((?:https?:)?\/\/)?((?:www|m)\.)?((?:youtube\.com|youtu.be))(\/(?:[\w\-]+\?v=|embed\/|v\/)?)([\w\-]+)(\S+)?$")
compiledRegexDict['onlyVideoLinkRegex'] = onlyVideoLinkRegex


# Compile regex with upper case, otherwise many false positive character matches
bufferChars = r"*_~|`[]()'-.•,"
compiledRegexDict['bufferChars'] = bufferChars
bufferMatch, addBuffers = "\\*_~|`\\-\\.", re.escape(bufferChars) # Add 'buffer' chars
usernameConfuseRegex = re.compile(confusable_regex("Linus Tech Tips"))
m = bufferMatch
a = addBuffers
for word in usernameBlackWords:
  value = re.compile(confusable_regex(word.upper(), include_character_padding=True).replace(m, a))
  compiledRegexDict['usernameBlackWords'].append([word, value])
for word in usernameNovidBlackWords:
  value = re.compile(confusable_regex(word.upper(), include_character_padding=True).replace(m, a))
  compiledRegexDict['usernameNovidBlackWords'].append([word, value])
for word in blackAdWords:
  value = re.compile(confusable_regex(word.upper(), include_character_padding=True).replace(m, a))
  compiledRegexDict['blackAdWords'].append([word, value])
for word in redAdWords:
  value = re.compile(confusable_regex(word.upper(), include_character_padding=True).replace(m, a))
  compiledRegexDict['redAdWords'].append([word, value])
for word in yellowAdWords:
  value = re.compile(confusable_regex(word.upper(), include_character_padding=True).replace(m, a))
  compiledRegexDict['yellowAdWords'].append([word, value])
for word in exactRedAdWords:
  value = re.compile(confusable_regex(word.upper(), include_character_padding=False))
  compiledRegexDict['exactRedAdWords'].append([word, value])
for word in usernameRedWords:
  value = re.compile(confusable_regex(word.upper(), include_character_padding=True).replace(m, a))
  compiledRegexDict['usernameRedWords'].append([word, value])
for word in textObfuBlackWords:
  value = re.compile(confusable_regex(word.upper(), include_character_padding=True).replace(m, a))
  compiledRegexDict['textObfuBlackWords'].append([word, value])
for word in usernameObfuBlackWords:
  value = re.compile(confusable_regex(word.upper(), include_character_padding=True).replace(m, a))
  compiledRegexDict['usernameObfuBlackWords'].append([word, value])

for word in textExactBlackWords:
    compiledRegexDict['textExactBlackWords'].append(word)
    for word in textUpLowBlackWords:
      compiledRegexDict['textUpLowBlackWords'].append(word)

# Prepare All-domain Regex Expression
prepString = "\.("
first = True
for extension in rootDomainList:
  if first == True:
      prepString += extension
      first = False
  else:
      prepString = prepString + "|" + extension
sensitivePrepString = prepString + ")"
prepString = prepString + ")\/"
rootDomainRegex = re.compile(prepString)
sensitiveRootDomainRegex = re.compile(sensitivePrepString)

spamListExpressionsList = []
# Prepare spam domain regex
for domain in spamDomainsList:
  spamListExpressionsList.append(confusable_regex(domain.upper().replace(".", "⚫"), include_character_padding=False).replace("(?:⚫)", "(?:[^a-zA-Z0-9 ]{1,2})"))
for account in spamAccountsList:
  spamListExpressionsList.append(confusable_regex(account.upper(), include_character_padding=True).replace(m, a))
for thread in spamThreadsList:
  spamListExpressionsList.append(confusable_regex(thread.upper(), include_character_padding=True).replace(m, a))
spamListCombinedRegex = re.compile('|'.join(spamListExpressionsList))

# Prepare Multi Language Detection
turkish = 'ÇçŞşĞğİ'
germanic = 'ẞßÄä'
cyrillic = "гджзклмнпрстфхцчшщыэюяъь"
japanese = 'ァアィイゥウェエォオカガキギクグケゲコゴサザシジスズセゼソゾタダチヂテデトドナニヌネノハバパヒビピフブプヘベペホボポマミムメモャヤュユョヨラリルレロヮワヰヱヲンヴヵヶヷヸヹヺーヽヾヿぁあぃいぅうぇえぉおかがきぎぐけげこごさざしじすずせぜそぞただちぢっつづてでとどなにぬねのはばぱひびぴふぶぷへべぺほぼぽまみむめもゃやゅゆょよらりるれろゎわゐゑをんゔゕゖゝゞゟ'
languages = [['turkish', turkish, []], ['germanic', germanic, []], ['cyrillic', cyrillic, []], ['japanese', japanese, []]]
for item in languages:
  item[2] = make_char_set(item[1])

filterSettings = {
  'spammerNumbersSet': spammerNumbersSet, 
  'compiledNumRegex': compiledNumRegex, 
  'minNumbersMatchCount': minNumbersMatchCount, 
  #'usernameBlackCharsSet': usernameBlackCharsSet, 
  'spamGenEmojiSet': spamGenEmojiSet,
  'redAdEmojiSet': redAdEmojiSet,
  'yellowAdEmojiSet': yellowAdEmojiSet,
  'hrtSet': hrtSet,
  'lowAlSet': lowAlSet,
  'rootDomainRegex': rootDomainRegex,
  'compiledRegexDict': compiledRegexDict,
  'usernameConfuseRegex': usernameConfuseRegex,
  'languages': languages,
  'sensitive': sensitive,
  'sensitiveRootDomainRegex': sensitiveRootDomainRegex,
  'unicodeCategoriesStrip': unicodeCategoriesStrip,
  'spamListCombinedRegex': spamListCombinedRegex,
  }


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, re.Pattern):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


##############################################################################
with open("filterSettings.json", "w") as f:
    json.dump(filterSettings, f, ensure_ascii=False, cls=SetEncoder, indent=2, default=str)

##############################################################################

def filter(commentText : str, authorChannelName : str, authorChannelID : str, 
            parentAuthorChannelID : str, channelOwnerName : str):
    smartFilter = filterSettings
    # Receive Variables
    compiledRegexDict = smartFilter['compiledRegexDict']
    numberFilterSet = smartFilter['spammerNumbersSet']
    compiledNumRegex = smartFilter['compiledNumRegex']
    minNumbersMatchCount = smartFilter['minNumbersMatchCount']
    bufferChars = compiledRegexDict['bufferChars']
    #usernameBlackCharsSet = smartFilter['usernameBlackCharsSet']
    spamGenEmojiSet = smartFilter['spamGenEmojiSet']
    redAdEmojiSet = smartFilter['redAdEmojiSet']
    yellowAdEmojiSet = smartFilter['yellowAdEmojiSet']
    hrtSet = smartFilter['hrtSet']
    lowAlSet = smartFilter['lowAlSet']
    languages = smartFilter['languages']
    sensitive =  smartFilter['sensitive']
    rootDomainRegex = smartFilter['rootDomainRegex']
    # Spam Lists
    spamListCombinedRegex = smartFilter['spamListCombinedRegex']
    
    # if debugSingleComment == True: 
    #   if input("Sensitive True/False: ").lower() == 'true': sensitive = True
    #   else: sensitive = False
    
    # Check for sensitive smart mode  
    if sensitive:
      rootDomainRegex = smartFilter['sensitiveRootDomainRegex']
    
    def findOnlyObfuscated(regexExpression, originalWord, stringToSearch):
        # Confusable thinks s and f look similar, have to compensate to avoid false positive
        ignoredConfusablesConverter = {ord('f'):ord('s'),ord('s'):ord('f')} 
        result = re.findall(regexExpression, stringToSearch.lower())  
        if not result:
          return False
        else:
          for match in result:
            lowerWord = originalWord.lower()
            for char in compiledRegexDict['bufferChars']:
              match = match.strip(char)
            if match.lower() != lowerWord and match.lower() != lowerWord.translate(ignoredConfusablesConverter):
              return True
    
    def remove_unicode_categories(string):
        return "".join(char for char in string if unicodedata.category(char) not in filterSettings['unicodeCategoriesStrip'])
    
    def check_if_only_link(string):
        result = re.match(compiledRegexDict['onlyVideoLinkRegex'], string)
        if not result:
          return False
        elif result.group(0) and len(result.group(0)) == len(string):
          return True
        else:
          return False
    
    commentText = re.sub(' +', ' ', commentText)
    # https://stackoverflow.com/a/49695605/17312053
    commentText = "".join(k if k in bufferChars else "".join(v) for k,v in itertools.groupby(commentText, lambda c: c))
    commentText = remove_unicode_categories(commentText)

    authorChannelName = re.sub(' +', ' ', authorChannelName)
    authorChannelName = remove_unicode_categories(authorChannelName)

    # Processed Variables
    combinedString = authorChannelName + commentText
    combinedSet = utils.make_char_set(combinedString, stripLettersNumbers=True, stripPunctuation=True)
    textSet = set(commentText)
    #usernameSet = utils.make_char_set(authorChannelName)

    if authorChannelID == parentAuthorChannelID:
        pass
    elif len(numberFilterSet.intersection(combinedSet)) >= minNumbersMatchCount:
        return True
    elif compiledNumRegex.search(combinedString):
        return True
      # Black Tests
        #elif usernameBlackCharsSet.intersection(usernameSet):
        #  return True
    elif any(re.search(expression[1], authorChannelName) for expression in compiledRegexDict['usernameBlackWords']):
        return True
    # elif config['detect_sub_challenge_spam'] and any(re.search(expression[1], authorChannelName) for expression in compiledRegexDict['usernameNovidBlackWords']):
        # return True
    elif any(findOnlyObfuscated(expression[1], expression[0], combinedString) for expression in compiledRegexDict['blackAdWords']):
        return True
    elif any(findOnlyObfuscated(expression[1], expression[0], commentText) for expression in compiledRegexDict['textObfuBlackWords']):
        return True
    elif any(word in commentText.lower() for word in compiledRegexDict['textExactBlackWords']):
        return True
    elif any((word in commentText and not textSet.intersection(lowAlSet)) for word in compiledRegexDict['textUpLowBlackWords']):
        return True
    elif any(findOnlyObfuscated(expression[1], expression[0], authorChannelName) for expression in compiledRegexDict['usernameObfuBlackWords']):
        return True
    elif re.search(spamListCombinedRegex, combinedString):
        return True
    # elif config['detect_link_spam'] and check_if_only_link(commentText.strip()):
        # return True
    elif sensitive and re.search(smartFilter['usernameConfuseRegex'], authorChannelName):
        return True
    elif not sensitive and findOnlyObfuscated(smartFilter['usernameConfuseRegex'], channelOwnerName, authorChannelName):
        return True
      # Multi Criteria Tests
    else:
        # Defaults
        yellowCount = 0
        redCount = 0

        languageCount = 0
        for language in languages:
          if language[2].intersection(combinedSet):
            languageCount += 1

        # Yellow Tests
        if any(findOnlyObfuscated(expression[1], expression[0], combinedString) for expression in compiledRegexDict['yellowAdWords']):
          yellowCount += 1

        hrtTest = len(hrtSet.intersection(combinedSet))
        if hrtTest >= 2:
          if not sensitive:
            yellowCount += 1
          else:
            redCount += 1
        elif sensitive and hrtTest >= 1:
          yellowCount += 1

        if yellowAdEmojiSet.intersection(combinedSet):
          yellowCount += 1

        if not sensitive and spamGenEmojiSet.intersection(combinedSet):
          yellowCount += 1

        if combinedString.count('#') >= 5:
          yellowCount += 1

        if combinedString.count('\n') >= 10:
          yellowCount += 1

        if languageCount >= 2:
          yellowCount += 1

        if re.search(rootDomainRegex, combinedString.lower()):
          yellowCount += 1

        # Red Tests
        #if any(foundObfuscated(re.findall(expression[1], combinedString), expression[0]) for expression in compiledRegexDict['redAdWords']):
        if any(findOnlyObfuscated(expression[1], expression[0], combinedString) for expression in compiledRegexDict['redAdWords']):
          redCount += 1

        if any(re.search(expression[1], combinedString) for expression in compiledRegexDict['exactRedAdWords']):
          redCount += 1

        if redAdEmojiSet.intersection(combinedSet):
          redCount += 1

        if sensitive and spamGenEmojiSet.intersection(combinedSet):
          redCount += 1

        if any(re.search(expression[1], authorChannelName) for expression in compiledRegexDict['usernameRedWords']):
          redCount += 1

        # Calculate Score
        if yellowCount >= 3:
          return True
        elif redCount >= 2:
          return True
        elif redCount >= 1 and yellowCount >= 1:
          return True
        elif sensitive and redCount >= 1:
          return True
        return False

    return False


commentText = """💋Visit: -   https://bit.ly/3eBinrY    💦



1. Search my ID (handle) Michael_Amature36ss



2. Send me Hii... i will be online and join you on live cam"""

print(filter(commentText, "Michael 2- F**СК МЕ - СНЕCK MY РR0FILЕ", "321", "123", "Linus Tech Tips"))