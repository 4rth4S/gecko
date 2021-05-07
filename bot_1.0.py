from telegram.ext import Updater, CommandHandler, ConversationHandler,CallbackQueryHandler, CallbackContext, Filters , MessageHandler
from telegram import InlineKeyboardMarkup,InlineKeyboardButton, Update ,ReplyKeyboardMarkup
import yaml, logging, os
import extract
import requests
import telegram
from QRmisp import load_iocs

#logging.basicConfig(
#    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
#)

#logger = logging.getLogger(__name__)

# Stages
FIRST, SECOND ,THIRD, FOUR, INPUT_TEXT_C= range(5)

# Types
URL, IPSRC, IPDST, DOMAIN, SHA256, MD5 = 'url','ip-src','ip-dst','domain','sha256','md5'

text = ""
tipo = ""
categoria = ""
refset = ""
GRUPO = -123456789   #'-412399331'

def start(update: Update, _: CallbackContext) -> str:
    user = update.message.from_user
    logger.info("User %s started the conversation.", user.first_name)
    keyboard = [
        [
            InlineKeyboardButton ('URL',callback_data=(URL))],
            [InlineKeyboardButton ('IPSRC',callback_data=(IPSRC))],
            [InlineKeyboardButton ('IPDST',callback_data=(IPDST))],
            [InlineKeyboardButton ('SHA256',callback_data=(SHA256))],
            [InlineKeyboardButton ('DOMAIN',callback_data=(DOMAIN))],
            [InlineKeyboardButton ('MD5',callback_data=(MD5))]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    update.message.reply_text("..Elegí el tipo de IoC que vas a cargar..", reply_markup=reply_markup)
    return FIRST


def updateIoc(update, context):  
    global text  
    text = update.message.text 
    try:
        if tipo or categoria != '':
            if(extract.buscar(text) != ""):
                buttonSI = InlineKeyboardButton (
                    text='SI',
                    callback_data='SI'
                )
                buttonNO = InlineKeyboardButton (
                    text='NO',
                    callback_data='NO'
                )
                update.message.reply_text('Se recibieron los IoC, procederé a cargar en MISP lo siguiente:\n%s\n ¿Confirmar?' % extract.buscar(text),reply_markup=InlineKeyboardMarkup([
                    [buttonSI,buttonNO]
                ]))
                return INPUT_TEXT_C            
            else:
                update.message.reply_text('No encuentro IoC válidos en tu mensaje. Recordá que solo acepto SHA256, MD5, IPs públicas y dominios/urls')
                return ConversationHandler.END
        else:
            update.message.reply_text('Por favor ejecutá un comando start , ya que falta definir el tipo y la categoria del IOC que desea cargar')
            return ConversationHandler.END
    except:
        logger.error('Algo raro paso en la funcion updateIoc.. ')

def confirmar_ioc_button(update,context):
    global text
    try:
        if(update.callback_query.data=='SI'):
            # aca va ir la llamada al modulo de carga en MISP
            extract.extraer(text, categoria, tipo)
            # aca va ir la llamada al modulo de carga en MISP
            update.callback_query.message.reply_text('confirmado, se cargaron!')
                
        if(update.callback_query.data=='NO'):
            update.callback_query.message.reply_text('se anulo la carga!')
            
        text=""
        return ConversationHandler.END
    except:
        logger.error('Algo raro paso en la funcion updateIoc.. ')

def url(update: Update, _: CallbackContext) -> str:
    """Show new choice of buttons"""
    query = update.callback_query
    global tipo
    tipo = query.data
    query.answer()
    keyboard = [
        [
            InlineKeyboardButton('Network activity', callback_data='Network activity')],
            [InlineKeyboardButton('External analysis', callback_data='External analysis')],
            [InlineKeyboardButton('Payload delivery', callback_data='Payload delivery')       ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    query.edit_message_text(
        text="..Bien, ahora elegí la categoría a la que aplica", reply_markup=reply_markup
    )
    return SECOND

def ipsrc(update: Update, _: CallbackContext) -> str:
    """Show new choice of buttons"""
    query = update.callback_query
    global tipo
    tipo = query.data
    query.answer()
    keyboard = [
        [
            InlineKeyboardButton('Network activity', callback_data='Network activity')],
            [InlineKeyboardButton('External analysis', callback_data='External analysis')],
            [InlineKeyboardButton('Payload delivery', callback_data='Payload delivery')       
    ]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    query.edit_message_text(
        text="..Bien, ahora elegí la categoría a la que aplica", reply_markup=reply_markup
    )
    return SECOND

def ipdst(update: Update, _: CallbackContext) -> str:
    """Show new choice of buttons"""
    query = update.callback_query
    global tipo
    tipo = query.data
    query.answer()
    keyboard = [
        [
            InlineKeyboardButton('Network activity', callback_data='Network activity')],
            [InlineKeyboardButton('External analysis', callback_data='External analysis')],
            [InlineKeyboardButton('Payload delivery', callback_data='Payload delivery')
    ]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    query.edit_message_text(
        text="..Bien, ahora elegí la categoría a la que aplica", reply_markup=reply_markup
    )
    return SECOND

def domain(update: Update, _: CallbackContext) -> str:
    """Show new choice of buttons"""
    query = update.callback_query
    global tipo
    tipo = query.data
    query.answer()
    keyboard = [
        [
            InlineKeyboardButton('Network activity', callback_data='Network activity')],
            [InlineKeyboardButton('External analysis', callback_data='External analysis')],
            [InlineKeyboardButton('Payload delivery', callback_data='Payload delivery')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    query.edit_message_text(
        text="..Bien, ahora elegí la categoría a la que aplica..", reply_markup=reply_markup
    )
    return SECOND

def sha256(update: Update, _: CallbackContext) -> str:
    query = update.callback_query
    global tipo
    tipo = query.data
    query.answer()
    keyboard = [
            
            [InlineKeyboardButton('Payload delivery', callback_data='Payload delivery')],
            [InlineKeyboardButton('Artifacts dropped', callback_data='Artifacts dropped')],
            [InlineKeyboardButton('Payload installation', callback_data='Payload installation')],
            [InlineKeyboardButton('External analysis', callback_data='External analysis')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    query.edit_message_text(
        text="..Bien, ahora elegí la categoría a la que aplica..", reply_markup=reply_markup
    )
    print("SHA256  :"  +SHA256)
    return SECOND

def md5(update: Update, _: CallbackContext) -> str:
  query = update.callback_query
  global tipo
  tipo = query.data
  query.answer()
  keyboard = [
      [
          InlineKeyboardButton('Payload delivery', callback_data='Payload delivery')],
          [InlineKeyboardButton('Artifacts dropped', callback_data='Artifacts dropped')],
          [InlineKeyboardButton('Payload installation', callback_data='Payload installation')],
          [InlineKeyboardButton('External analysis', callback_data='External analysis')
      ] 
  ]
  reply_markup = InlineKeyboardMarkup(keyboard)
  query.edit_message_text(
      text='..Bien, ahora elegí la categoría a la que aplica',reply_markup=reply_markup
      )
  return SECOND

def definir_categoria(update,context):
    global categoria
    global tipo
    query = update.callback_query
    categoria = query.data
    query.answer()
    query.edit_message_text(text='Elegiste el tipo de ioc = '+tipo+' y la categoria = '+categoria+'.\n \
    Pasame los indicadores de compromiso así los parseo , y los agrego a misp. Por favor recorda anteponer: \n \
    /ioc a los indicadores.')
    return tipo, categoria

def start_push(update: Update, _: CallbackContext) -> str:
    user = update.message.from_user
    logger.info("User %s started the conversation.", user.first_name)
    keyboard = [
        [
            InlineKeyboardButton ('URL',callback_data='URL')],
            [InlineKeyboardButton ('IPSRC',callback_data='IPSRC')],
            [InlineKeyboardButton ('IPDST',callback_data='IPDST')],
            [InlineKeyboardButton ('SHA256',callback_data='SHA256')],
            [InlineKeyboardButton ('DOMAIN',callback_data='DOMAIN')],
            [InlineKeyboardButton ('MD5',callback_data='MD5')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    update.message.reply_text("..Elegí el tipo de IoC que queres pushear a QRadar..", reply_markup=reply_markup)
    return THIRD


def setear_referenceSet(update: Update, _: CallbackContext) -> str:
    query = update.callback_query
    global tipo
    global refset
    tipo = query.data
    logger.info('El tipo es  '+tipo+' , ahora vamos a setear el refset')
    if tipo == 'DOMAIN':
      refset = '_MISP_Event_IOC_DOMAIN'
    elif tipo == 'IPDST':
      refset = '_MISP_Event_IOC_DSTIP'
    elif tipo == 'MD5':
      refset = '_MISP_Event_IOC_MD5'
    elif tipo == 'SHA256':
      refset = '_MISP_Event_IOC_SHA256'
    elif tipo == 'IPSRC':
      refset = '_MISP_Event_IOC_SRCIP'
    elif tipo == 'URL':
      refset = '_MISP_Event_IOC_URLS'
    else:
      logger.error('el referenceSet no se pudo setear porque se cargo algun valor fuera de los IOCS permitidos')
    logger.info('el tipo es '+tipo+', y el referenceSet es '+refset+' . Vamos al step FOUR. ' )
    

    buttonSI = InlineKeyboardButton (text='SI',callback_data='SI')
    buttonNO = InlineKeyboardButton (text='NO',callback_data='NO')
    
    reply_markup = InlineKeyboardMarkup([[buttonSI,buttonNO]])
    update.callback_query.message.reply_text(text='el tipo elegido es:  '+tipo+' .\n Es correcto?.', reply_markup=reply_markup)
    return FOUR

def push_attributes(update: Update, _: CallbackContext) -> str:
    logger.info('entrando a push attributes...' )
    query=update.callback_query
    global refset
    global tipo
    if query.data == 'SI':
        try:
            number_of_iocs=load_iocs(tipo, refset, 40)
        except:
            logger.error('No se pudo ejecutar load_iocs del módulo QRmisp. ')
            logger.info('La cant de IOCS son: '+number_of_iocs+' .' )
        #    query.
    #       update.message.reply_text('Se pushearon '+number_of_iocs+' IOCS hacia Qradar. Gracias, interactuamos luego.')
        if str(number_of_iocs) == '0':
            update.callback_query.message.reply_text('No se cargaron indicadores nuevos.')
        else:
            update.callback_query.message.reply_text('confirmado, se cargaron : '+number_of_iocs+' nuevos en QR.')
    else:
        update.callback_query.message.reply_text('Se canceló la carga de IOCS.')
    return ConversationHandler.END

if __name__ == '__main__':

    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
    logger = logging.getLogger('gecko_Bot')
    
    # Llave API para conectarse a Telegram 
    updater = Updater(token="1574109532:AAgTNhRK0DKiMS7ei4n2qnYYMhA8yvdb2sz", use_context=True)

    dp = updater.dispatcher

    # Handler'sZZZ 
    start_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            FIRST: [
                CallbackQueryHandler(url, pattern='^' + URL + '$'),  # Boton >> Callback_data >> url
                CallbackQueryHandler(ipsrc, pattern='^' + IPSRC + '$'),
                CallbackQueryHandler(ipdst, pattern='^' + IPDST + '$'),
                CallbackQueryHandler(domain, pattern='^' + DOMAIN + '$'),
                CallbackQueryHandler(sha256, pattern='^' + SHA256 + '$'),
                CallbackQueryHandler(md5, pattern='^' + MD5 + '$')
            ],
            SECOND: [
                CallbackQueryHandler(definir_categoria, pattern='^'+"Payload delivery"+ '$'),
                CallbackQueryHandler(definir_categoria, pattern='^'+"Artifacts dropped"+ '$'),
                CallbackQueryHandler(definir_categoria, pattern='^'+"Payload installation"+ '$'),
                CallbackQueryHandler(definir_categoria, pattern='^'+"External analysis"+ '$'),
                CallbackQueryHandler(definir_categoria, pattern='^'+"Network activity"+ '$')
            ],
        },
        fallbacks=[CommandHandler('start', start)],
    )
    # Add ConversationHandlers to dispatcher that will be used for handling
    # updates
    dp.add_handler(start_handler)

    dp.add_handler(ConversationHandler(
        entry_points=[
            CommandHandler('ioc', updateIoc)
        ],
        states={
            
            INPUT_TEXT_C: [CallbackQueryHandler(callback=confirmar_ioc_button)]
        },
        fallbacks=[CommandHandler('start', start)]
    ))
    
    push_handler = ConversationHandler(
        entry_points= [CommandHandler('push', start_push)],
        states={
            THIRD: [
                CallbackQueryHandler(setear_referenceSet, pattern='^'+'URL'+'$'),
                CallbackQueryHandler(setear_referenceSet, pattern='^'+'IPSRC'+'$'),
                CallbackQueryHandler(setear_referenceSet, pattern='^'+'IPDST'+'$'),
                CallbackQueryHandler(setear_referenceSet, pattern='^'+'SHA256'+'$'),
                CallbackQueryHandler(setear_referenceSet, pattern='^'+'DOMAIN'+'$'),
                CallbackQueryHandler(setear_referenceSet, pattern='^'+'MD5'+'$')
            ]
        },
        fallbacks=[CommandHandler('push', start_push)]
    )
    dp.add_handler(push_handler)
    updater.start_polling()
    updater.idle()
