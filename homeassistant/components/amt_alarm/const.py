"""Constants for the Intelbras AMT Alarms integration."""

DOMAIN = "amt_alarm"

AMT_EVENT_CODE_EMERGENCIA_MEDICA = 1100
AMT_EVENT_CODE_DISPARO_OU_PANICO_DE_INCENDIO = 1110
AMT_EVENT_CODE_PANICO_AUDIVEL_OU_SILENCIOSO = 1120
AMT_EVENT_CODE_SENHA_DE_COACAO = 1121
AMT_EVENT_CODE_PANICO_SILENCIOSO = 1122
AMT_EVENT_CODE_DISPARO_DE_ZONA = 1130
AMT_EVENT_CODE_DISPARO_DE_CERCA_ELETRICA = 1131
AMT_EVENT_CODE_DISPARO_DE_ZONA_24H = 1133
AMT_EVENT_CODE_TAMPER_DO_TECLADO = 1145
AMT_EVENT_CODE_DISPARO_SILENCIOSO = 1146
AMT_EVENT_CODE_FALHA_DA_SUPERVISAO_SMART = 1147
AMT_EVENT_CODE_SOBRECARGA_NA_SAIDA_AUXILIAR = 1300
AMT_EVENT_CODE_FALHA_NA_REDE_ELETRICA = 1301
AMT_EVENT_CODE_BATERIA_PRINCIPAL_BAIXA_OU_EM_CURTO_CIRCUITO = 1302
AMT_EVENT_CODE_RESET_PELO_MODO_DE_PROGRAMACAO = 1305
AMT_EVENT_CODE_ALTERACAO_DA_PROGRAMACAO_DO_PAINEL = 1306
AMT_EVENT_CODE_BATERIA_PRINCIPAL_AUSENTE_OU_INVERTIDA = 1311
AMT_EVENT_CODE_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE = 1321
AMT_EVENT_CODE_TOQUE_DE_PORTEIRO = 1322
AMT_EVENT_CODE_PROBLEMA_EM_TECLADO_OU_RECEPTOR = 1333
AMT_EVENT_CODE_FALHA_NA_LINHA_TELEFONICA = 1351
AMT_EVENT_CODE_FALHA_AO_COMUNICAR_EVENTO = 1354
AMT_EVENT_CODE_CORTE_DA_FIACAO_DOS_SENSORES = 1371
AMT_EVENT_CODE_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES = 1372
AMT_EVENT_CODE_TAMPER_DO_SENSOR = 1383
AMT_EVENT_CODE_BATERIA_BAIXA_DE_SENSOR_SEM_FIO = 1384
AMT_EVENT_CODE_DESATIVACAO_PELO_USUARIO = 1401
AMT_EVENT_CODE_AUTO_DESATIVACAO = 1403
AMT_EVENT_CODE_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE = 1407
AMT_EVENT_CODE_ACESSO_REMOTO_PELO_SOFTWARE_DE_DOWNLOAD_UPLOAD = 1410
AMT_EVENT_CODE_FALHA_NO_DOWNLOAD = 1413
AMT_EVENT_CODE_ACIONAMENTO_DE_PGM = 1422
AMT_EVENT_CODE_SENHA_INCORRETA = 1461
AMT_EVENT_CODE_ANULACAO_TEMPORARIA_DE_ZONA = 1570
AMT_EVENT_CODE_ANULACAO_POR_DISPARO = 1573
AMT_EVENT_CODE_TESTE_MANUAL = 1601
AMT_EVENT_CODE_TESTE_PERIODICO = 1602
AMT_EVENT_CODE_SOLICITACAO_DE_MANUTENCAO = 1616
AMT_EVENT_CODE_RESET_DO_BUFFER_DE_EVENTOS = 1621
AMT_EVENT_CODE_LOG_DE_EVENTOS_CHEIO = 1624
AMT_EVENT_CODE_DATA_E_HORA_FORAM_REINICIADAS = 1625
AMT_EVENT_CODE_RESTAURACAO_DE_INCENDIO = 3110
AMT_EVENT_CODE_RESTAURACAO_DISPARO_DE_ZONA = 3130
AMT_EVENT_CODE_RESTAURACAO_DE_DISPARO_DE_CERCA_ELETRICA = 3131
AMT_EVENT_CODE_RESTARAUCAO_DISPARO_DE_ZONA_24H = 3133
AMT_EVENT_CODE_RESTARAUCAO_TAMPER_DO_TECLADO = 3145
AMT_EVENT_CODE_RESTARAUCAO_DISPARO_SILENCIOSO = 3146
AMT_EVENT_CODE_RESTARAUCAO_DA_SUPERVISAO_SMART = 3147
AMT_EVENT_CODE_RESTARAUCAO_SOBRECARGA_NA_SAIDA_AUXILIAR = 3300
AMT_EVENT_CODE_RESTARAUCAO_FALHA_NA_REDE_ELETRICA = 3301
AMT_EVENT_CODE_RESTARAUCAO_BAT_PRINC_BAIXA_OU_EM_CURTO_CIRCUITO = 3302
AMT_EVENT_CODE_RESTARAUCAO_BAT_PRINC_AUSENTE_OU_INVERTIDA = 3311
AMT_EVENT_CODE_RESTARAUCAO_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE = 3321
AMT_EVENT_CODE_RESTARAUCAO_PROBLEMA_EM_TECLADO_OU_RECEPTOR = 3333
AMT_EVENT_CODE_RESTARAUCAO_LINHA_TELEFONICA = 3351
AMT_EVENT_CODE_RESTARAUCAO_CORTE_DA_FIACAO_DOS_SENSORES = 3371
AMT_EVENT_CODE_RESTARAUCAO_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES = 3372
AMT_EVENT_CODE_RESTARAUCAO_TAMPER_DO_SENSOR = 3383
AMT_EVENT_CODE_RESTARAUCAO_BATERIA_BAIXA_DE_SENSOR_SEM_FIO = 3384
AMT_EVENT_CODE_ATIVACAO_PELO_USUARIO = 3401
AMT_EVENT_CODE_AUTO_ATIVACAO = 3403
AMT_EVENT_CODE_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE = 3407
AMT_EVENT_CODE_ATIVACAO_POR_UMA_TECLA = 3408
AMT_EVENT_CODE_DESACIONAMENTO_DE_PGM = 3422
AMT_EVENT_CODE_ATIVACAO_PARCIAL = 3456
AMT_EVENT_CODE_KEEP_ALIVE = -2

AMT_EVENT_EMERGENCIA_MEDICA = "Emergência Médica"
AMT_EVENT_DISPARO_OU_PANICO_DE_INCENDIO = "Disparo ou pânico de incêndio"
AMT_EVENT_PANICO_AUDIVEL_OU_SILENCIOSO = "Pânico audível ou silencioso"
AMT_EVENT_SENHA_DE_COACAO = "Senha de coação"
AMT_EVENT_PANICO_SILENCIOSO = "Pânico silencioso"
AMT_EVENT_DISPARO_DE_ZONA = "Disparo de zona"
AMT_EVENT_DISPARO_DE_CERCA_ELETRICA = "Disparo de cerca elétrica"
AMT_EVENT_DISPARO_DE_ZONA_24H = "Disparo de zona 24h"
AMT_EVENT_TAMPER_DO_TECLADO = "Tamper do teclado"
AMT_EVENT_DISPARO_SILENCIOSO = "Disparo silencioso"
AMT_EVENT_FALHA_DA_SUPERVISAO_SMART = "Falha da supervisão Smart"
AMT_EVENT_SOBRECARGA_NA_SAIDA_AUXILIAR = "Sobrecarga na saída auxiliary"
AMT_EVENT_FALHA_NA_REDE_ELETRICA = "Falha na rede elétrica"
AMT_EVENT_BATERIA_PRINCIPAL_BAIXA_OU_EM_CURTO_CIRCUITO = (
    "Bateria principal baixa ou em curto-circuito"
)
AMT_EVENT_RESET_PELO_MODO_DE_PROGRAMACAO = "Reset pelo modo de programação"
AMT_EVENT_ALTERACAO_DA_PROGRAMACAO_DO_PAINEL = "Alteração da programação do painel"
AMT_EVENT_BATERIA_PRINCIPAL_AUSENTE_OU_INVERTIDA = (
    "Bateria principal ausente ou invertida"
)
AMT_EVENT_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE = "Corte ou curto-circuito na sirene"
AMT_EVENT_TOQUE_DE_PORTEIRO = "Toque de porteiro"
AMT_EVENT_PROBLEMA_EM_TECLADO_OU_RECEPTOR = "Problema em teclado ou receptor"
AMT_EVENT_FALHA_NA_LINHA_TELEFONICA = "Falha na linha telefônica"
AMT_EVENT_FALHA_AO_COMUNICAR_EVENTO = "Falha ao comunicar evento"
AMT_EVENT_CORTE_DA_FIACAO_DOS_SENSORES = "Corte da fiação dos sensores"
AMT_EVENT_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES = (
    "Curto-circuito na fiação dos sensores"
)
AMT_EVENT_TAMPER_DO_SENSOR = "Tamper do sensor"
AMT_EVENT_BATERIA_BAIXA_DE_SENSOR_SEM_FIO = "Bateria baixa de sensor sem fio"
AMT_EVENT_DESATIVACAO_PELO_USUARIO = "Desativação pelo usuário"
AMT_EVENT_AUTO_DESATIVACAO = "Auto-desativação"
AMT_EVENT_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE = (
    "Desativação via computador ou telefone"
)
AMT_EVENT_ACESSO_REMOTO_PELO_SOFTWARE_DE_DOWNLOAD_UPLOAD = (
    "Acesso remoto pelo software de download/upload"
)
AMT_EVENT_FALHA_NO_DOWNLOAD = "Falha no download"
AMT_EVENT_ACIONAMENTO_DE_PGM = "Acionamento de PGM"
AMT_EVENT_SENHA_INCORRETA = "Senha incorreta"
AMT_EVENT_ANULACAO_TEMPORARIA_DE_ZONA = "Anulação temporária de zona"
AMT_EVENT_ANULACAO_POR_DISPARO = "Anulação por disparo"
AMT_EVENT_TESTE_MANUAL = "Teste manual"
AMT_EVENT_TESTE_PERIODICO = "Teste periódico"
AMT_EVENT_SOLICITACAO_DE_MANUTENCAO = "Solicitação de manutenção"
AMT_EVENT_RESET_DO_BUFFER_DE_EVENTOS = "Reset do buffer de eventos"
AMT_EVENT_LOG_DE_EVENTOS_CHEIO = "Log de eventos cheio"
AMT_EVENT_DATA_E_HORA_FORAM_REINICIADAS = "Data e hora foram reiniciadas"
AMT_EVENT_RESTAURACAO_DE_INCENDIO = "Restauração de incêndio"
AMT_EVENT_RESTAURACAO_DISPARO_DE_ZONA = "Restauração disparo de zona"
AMT_EVENT_RESTAURACAO_DE_DISPARO_DE_CERCA_ELETRICA = (
    "Restauração de disparo de cerca elétrica"
)
AMT_EVENT_RESTARAUCAO_DISPARO_DE_ZONA_24H = "Restauração disparo de zona 24h"
AMT_EVENT_RESTARAUCAO_TAMPER_DO_TECLADO = "Restauração tamper do teclado"
AMT_EVENT_RESTARAUCAO_DISPARO_SILENCIOSO = "Restauração disparo silencioso"
AMT_EVENT_RESTARAUCAO_DA_SUPERVISAO_SMART = "Restauração da supervisão Smart"
AMT_EVENT_RESTARAUCAO_SOBRECARGA_NA_SAIDA_AUXILIAR = (
    "Restauração sobrecarga na saída auxiliary"
)
AMT_EVENT_RESTARAUCAO_FALHA_NA_REDE_ELETRICA = "Restauração falha na rede elétrica"
AMT_EVENT_RESTARAUCAO_BAT_PRINC_BAIXA_OU_EM_CURTO_CIRCUITO = (
    "Restauração bat. princ. baixa ou em curto-circuito"
)
AMT_EVENT_RESTARAUCAO_BAT_PRINC_AUSENTE_OU_INVERTIDA = (
    "Restauração bat. princ. ausente ou invertida"
)
AMT_EVENT_RESTARAUCAO_CORTE_OU_CURTO_CIRCUITO_NA_SIRENE = (
    "Restauração corte ou curto-circuito na sirene"
)
AMT_EVENT_RESTARAUCAO_PROBLEMA_EM_TECLADO_OU_RECEPTOR = (
    "Restauração problema em teclado ou receptor"
)
AMT_EVENT_RESTARAUCAO_LINHA_TELEFONICA = "Restauração linha telefônica"
AMT_EVENT_RESTARAUCAO_CORTE_DA_FIACAO_DOS_SENSORES = (
    "Restauração corte da fiação dos sensores"
)
AMT_EVENT_RESTARAUCAO_CURTO_CIRCUITO_NA_FIACAO_DOS_SENSORES = (
    "Restauração curto-circuito na fiação dos sensores"
)
AMT_EVENT_RESTARAUCAO_TAMPER_DO_SENSOR = "Restauração tamper do sensor"
AMT_EVENT_RESTARAUCAO_BATERIA_BAIXA_DE_SENSOR_SEM_FIO = (
    "Restauração bateria baixa de sensor sem fio"
)
AMT_EVENT_ATIVACAO_PELO_USUARIO = "Ativação pelo usuário"
AMT_EVENT_AUTO_ATIVACAO = "Auto-ativação"
AMT_EVENT_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE = "Ativação via computador ou telefone"
AMT_EVENT_ATIVACAO_POR_UMA_TECLA = "Ativação por uma tecla"
AMT_EVENT_DESACIONAMENTO_DE_PGM = "Desacionamento de PGM"
AMT_EVENT_ATIVACAO_PARCIAL = "Ativação parcial"
AMT_EVENT_KEEP_ALIVE = "Keep-Alive"
