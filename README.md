# ⚡ Oukitel Cloud Bridge (Experimental)

[![Unofficial](https://img.shields.io/badge/status-UNOFFICIAL%20%2F%20community-red)]()
[![Experimental](https://img.shields.io/badge/stability-experimental-orange)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

> ⚠️ **PROGETTO NON UFFICIALE — DISCLAIMER IMPORTANTE**
>
> Questo add-on è un progetto open-source della community e **NON è affiliato, approvato,
> sponsorizzato o supportato da Oukitel** o da qualsiasi altra azienda menzionata.
>
> Il marchio **Oukitel®** è di proprietà esclusiva dei rispettivi titolari.
> L'uso di questo software avviene **sotto la propria responsabilità**.
>
> Per il supporto ufficiale del dispositivo fare riferimento **esclusivamente** all'app
> ufficiale Oukitel e ai canali di supporto ufficiali del produttore.
>
> Questo progetto non viola i Termini di Servizio di Oukitel in quanto utilizza
> esclusivamente le credenziali dell'utente (email e password) per accedere
> al proprio account, esattamente come farebbe l'app ufficiale.

---

> 🚧 **STATO: SPERIMENTALE**
>
> - ✅ **Sensori** — funzionanti (dati letti dal cloud via polling HTTP)
> - ✅ **Switch AC/DC** — funzionanti
> - ✅ **AC Charging Limit** — slider 0–100% funzionante
>
> ### ✅ Dispositivi testati
>
> | Modello | App | Note |
> |---|---|---|
> | **OUKITEL P1000 Plus** (`P1000EPLUS`) | Wonderfree | Testato su hardware reale |
>
> Se hai un altro dispositivo Oukitel e funziona, apri una Issue o una Pull Request!

---

## 📱 Prerequisiti — Account app Wonderfree o Landbook

I dispositivi Oukitel utilizzano l'infrastruttura cloud Acceleronix, la stessa usata
dalle app **Wonderfree** e **Landbook**. Per usare questo bridge devi avere un account
attivo su una di queste app e aver registrato il dispositivo tramite essa.

| App utilizzata | Valore `app` da usare |
|---|---|
| **Wonderfree** | `wonderfree` |
| **Landbook** | `landbook` |

> ✅ Il bridge usa le stesse credenziali dell'app (email e password).
> Non crea account separati e non aggira alcuna protezione di sicurezza.
>
> ❌ Non è possibile usare questo bridge senza un account valido su Wonderfree o Landbook.

---

## ⚙️ Configurazione

| Campo | Descrizione |
|---|---|
| `wf_email` | Email del tuo account Wonderfree o Landbook |
| `wf_password` | Password del tuo account Wonderfree o Landbook |
| `device_key` | Chiave dispositivo (dai log del cloud all'avvio) |
| `mqtt_host` | Host broker MQTT (default: `core-mosquitto`) |
| `mqtt_port` | Porta broker MQTT (default: `1883`) |

---

## 📊 Sensori disponibili

| Sensore | Unità | Note |
|---|---|---|
| Battery Capacity | % | Batteria principale |
| Remaining Available Time | min | Tempo rimanente a piena potenza |
| Remaining Charging Time | min | Tempo rimanente alla ricarica completa |
| Device Temperature | °C | Temperatura interna |
| Total Input Power | W | Potenza totale in ingresso |
| Total Output Power | W | Potenza totale in uscita |
| AC Charging Input | W | Potenza ricarica AC |
| PV Charging Input | W | Potenza pannelli solari |
| AC1 Output Power | W | Uscita AC1 |
| AC1 Output Voltage | V | Tensione uscita AC1 |
| 12V Output Power | W | Uscita DC 12V |
| 24V Output Power | W | Uscita DC 24V |
| USB-A / USB-C Output | W | Uscite USB |
| TypeC1 / TypeC2 Output | W | Uscite Type-C |
| Cooling Fan | — | Stato ventola |
| Output Voltage Setting | V | Impostazione tensione uscita |
| Output Frequency Setting | Hz | Impostazione frequenza uscita |

---

## ❌ Limitazioni note

**AC/DC Switch non funzionanti:**
I comandi HEX per accendere/spegnere le uscite AC e DC **non sono stati verificati
su hardware reale** e probabilmente non funzionano sul tuo dispositivo.

Per trovare i comandi corretti è necessario catturarli dall'app Oukitel ufficiale
tramite Frida (dynamic instrumentation). Se hai un dispositivo Oukitel e vuoi
contribuire, apri una Issue su GitHub.

---

## 🔒 Privacy e sicurezza

Quando condividi log o screenshot per supporto:
- Oscura sempre email e password
- Oscura il token Bearer
- Oscura `device_key` se vuoi mantenerlo privato

---

## 📄 Licenza

MIT — questo progetto non è affiliato con Oukitel o Acceleronix.
