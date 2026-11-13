// Palavras do minigame diário (5 letras, sem acento: "avião" vira "aviao").
// ANSWERS: palavras que podem ser sorteadas (comuns, sem plural nem verbo conjugado).
// EXTRA_GUESSES: palavras aceitas como tentativa, mas que nunca são sorteadas.

const ANSWERS_TEXT = `
abrir acaso achar acima adeus agora aguia ainda ajuda alado algum altar aluno amada amado
amiga amigo andar anexo animo antes anual apoio arado areia arena arroz assar astro atlas
atual audio autor avela aviao baile baixo balao balde banco banda banho barco barro bater
beber beijo bicho bingo bispo blusa bolsa bolso bomba borda botao braco brava bravo breve
briga brisa bruma bruxa burro busca cabra cacau cacho caixa calda caldo calma calmo calor
campo canal canoa canto capaz capim carga carne carro carta casal casca casco causa cavar
cerca certo cesta chave chefe chuva ciclo cinco cinto cisne civil claro clima cobra cofre
coisa coral corda corpo corte couro couve cravo creme crime cruel culpa curso curto curva
danca dardo dente dever disco dizer docil domar drama duelo durar duque ebano elite enfim
entre envio epoca estar etapa exato exito extra facil faixa falar falha falso farol fatia
fauna favor fazer febre feira feliz fenda feroz festa ficar filho filme final firma firme
flora folha fonte forca forma forno forte fosso fraco frase freio frevo fruta fruto fugir
fundo fungo furia furor gaita galho ganso garfo garra geada genio gente gesto girar globo
golpe gordo gorro gosto grade grama grato grave grilo grito grupo gruta haver heroi hiena
hotel humor ideia idolo igual imune jarra jarro jeito jogar jovem juizo junho junto justo
lagoa lapis largo laser lavar leite lenco lenha lenta lento leque lesma levar libra lider
limao limbo limpo linda lindo linha lirio lista litro livre livro local lombo longe louco
louro lugar lutar macio magia magro maior malha manga manha mania manto marca marco marte
massa meiga meigo melao menor menta mesmo metal metro mexer milho mirar misto moeda moita
molho monte morar morro mosca motor mover muito mundo museu nacao nadar natal naval navio
nevoa ninho nivel nobre noite norte nuvem oasis obter olhar ombro ontem opcao ordem orgao
ouvir pacto padre pagar palco palma papel parar parte passo pasta patio pausa pavao pedal
pedra peixe perto pesca piano pilha pinho pista plano pluma pobre poder polvo ponte ponto
porco porta posse potro pouco prado praia prata prato prazo preco presa prova pulga pular
pulso quase queda rampa rapaz rasgo razao regra reino remar risco ritmo rocha roupa rumor
sabao saber sabor sadio safra saida salao salto samba sauna seiva selva senha senso serra
sinal sitio sobre socio solar solda sonho sopro sorte suave subir sumir susto tacho talco
tampa tanto tarde tecla tecer telha temor tempo tenda tenis terno terra teste texto tigre
tinta tirar toldo tomar torre total touro traje trapo trevo tribo trigo troca trono tropa
turma turno unico usina vagao valor vapor varal vazio velho venda vento verao verba verde
verso video vigor vinho virar visao vista viver volta vulto zebra aroma banjo bolha brasa
cesto cinza colar conto crepe crina dueto fiapo harpa jaula lebre lince manso morsa ostra
palha pente perna pinca pires polen prego punho quilo sarau tiara tocha trena tutor vespa
viola zinco atriz bloco cacto cauda clube comum conde copia crise delta denso dieta digno
dobra ducha exame farsa fibra fluxo fobia forja frota fugaz fusao garoa golfo horta icone
inato irmao janta jejum juros labio lacre lapso latim leigo lucro lunar manta matiz medir
miolo molde mural nariz nervo noiva noivo norma nunca oeste opaco orfao outro panda pardo
peito perda pesar piada pisar pizza placa pleno podre poema poeta polar polpa pouso praga
prumo pudim puxar raiva ramal rigor rival rosto rouco ruivo rural sagaz salsa santo saque
saude secar sexta sigla signo solto somar sotao sutil tabua tenso tocar torto tosse traco
trama tubos turvo uniao usual valsa vasto vilao virus visor vital viuva vocal vogal voraz
xampu zelar
`;

const EXTRA_GUESSES_TEXT = `
colei colou cobre coque covil colho
asas bocas botas cafes camas canos casos cocos colos cores cubas damas dicas dores falas
fases fatos favas feras filas fitas fofos gatas guias jatos lamas lobas lucas luvas mamas
medos minas modas modos molas motos mudas musas natas naves novos nozes obras ovais pacas
papas patas pazes penas pipas pocos polos potes pulos rabos ratas redes regas rocas rolos
roxos sacos sagas setas socos sofas tacas teias temas times tipos tocas topos trens trios
tufos vales varas vezes vilas vozes graos ostras aneis bifes doces risos macas cocho
amou andou chamou ficou tirou virou lavou nadou pulou tocou notou ligou criou matou gerou
somou mexeu viveu sumiu feriu bebeu meteu mudei olhei tomei levei tirei virei lavei nadei
pulei notei criei matei gerei somei vendi perdi corri dormi parti senti menti venci
acham jogam pegam mudam olham tomam levam pagam tiram lavam nadam pulam tocam notam ligam
criam matam bebem vivem abrem sobem devem canto conto penso durmo corro vendo perco venho
ponho posso sinto minto faco trago canta conta pensa dorme corre vende perde tenta passa
chega deixa gosta ganha sente mente veste serve segue chora nasce morre vence ataca fecha
limpa pinta grita manda entra sorri acaba volta damos fomos demos
boiar bolar botar calar casar colar comer coser criar curar dancar ferir fixar fumar furar
jurar ligar matar mudar negar ousar picar remar rodar rugir selar socar sugar sujar temer
tecer adiar aliar armar arder atuar cegar cocar corar dopar falir filar frear latir minar
rapar ralar reger sanar sarar segar tracar visar votar gemer
abade abuso adega adubo afago afeto agito algoz amago anzol apuro arame arcos arduo arpao
atomo atroz autos avaro aveia azedo bagre baita balas bamba banir barao batom beata berro
besta bicos bioma birra bones borra botas bruto bucal bucho bufar burla cabal cacos calos
canil capuz carie casta catar caule cedro cegas cerco cervo chulo circo cisma clero clone
combo coice corja coroa corso costa coxas cozer credo crivo cromo cueca cuica cunha cupom
dedao deusa divas dobro dogma dolar donos doses dupla duplo duzia edema elfos enjoo epica
epico etica etico exodo farpa farra fatal ferro fetal fisco floco fluir folia fones fosco
frete fugas fuzil garbo gemeo genro ginga gleba glote gnomo goela gomas grana greve gripe
habil hidra hifen homem honra iates idade idoso ilheu impar irado jarda jegue jubas judeu
julho junco junta juras ladra lanca lance larva latao lavra leais leito lerdo letal levas
licor ligas linho lixao lixos loiro lorde lotes lousa lupas luxos macia mafia mamae manco
meada mexia midia milha mimar miojo miope mirra mitos moela mofar molar monge morna morno
mosto motim mudez mugir mulas multa murro musgo mutuo naipe nasal neves ninfa nisso nodoa
nulos obvio odios oleos oncas opera orcas otimo ousar ovino oxala pagao paiol palmo pampa
papai parca pares parvo pasto pauta pavor pelas peles peste pilar pinga pinos pique pisca
plebe pneus podio polia pomar pombo porao porca porte posar potes povos prima primo proas
pudor punir puros quais quina racao radar ranco rango ranho rasos raspa redea refem reles
relva renda reses resto retro reves rezas ricos rifle rinha rixas robes roido rolha rombo
rosca rouca ruela rumos russo sabia sacro saldo sanha sarda sarna secos senao senda sendo
serao serio serva servo setor sobra sogra sogro soldo solos sonda sovar suado sueca suite
sulco surdo surfe surra sushi sutis taipa talao talha talos tango tanga tapas tarja taxas
teima telao tenaz tenra tenro termo testa tibia tique tiras tocos todas todos tomos tonel
tonto toras torno tosco trago trato treco treno tripa troco trote trova trufa truta tumor
tunel turba uivar umido unhas urina usada usado uteis utero vacuo vagem vaias valas valia
varao vasta vazao veloz venal verbo verga vetor vicio vidro vigas vigia viril vivos voces
volei vossa vosso vulgo xales xeque
agora assim atras entao certa longa longo baixa feias feios fraca larga limpa novos rasos
sujas tensa tolas umida vazia velha vivas clara curta duras duros falsa frias frios gorda
justa leves magra morta morto rouca santa seria tonta vasta vinte treze preto preta roxas
lilas joelho testa bocas pesco cilio veias ursos corvo garca traca cupim lebre perus
torta mamao bolos sopas pudim aguas paes atum lombo trigo aveia balas
fogao vasos prato pente radio lapis regua manta meias calca saias aneis colar
vales riacho praca neves raios mares porto cais sitio forro graca risos choro licao
cartas damas truco placar fases itens chefe ogros runas pocao ouros rubis opala ambar
lives canal clipe audio fones robos drone bytes pixel
casas bolas gatos patos ratos lobos bolos copos sapos vacas velas sinos selos ramos rodas
lagos magos horas ilhas dados anjos armas artes belas cubos datas dunas ervas figos gelos
gemas hinos joias lemas mimos novas ossos pelos peras reais remos sucos vasos fogos raios
copas cenas dicas notas rosas fotos metas pecas sopas telas tetos vidas votos zonas alvos
areas bases caras dedos ditos fadas focas galos gotas jogos lados latas lojas luvas malas
matas mesas nomes ondas panos pesos pisos rimas rugas salas vagas olhos mapas tacos tiros
urnas veias picos leoes irmas eixos elmos ermos nabos tatus tolos sedas sujos
falou comeu abriu andou achou ficou pegou jogou mudou olhou tomou levou pagou falei andei
achei falam comem andam fazem dizem podem sabem temos somos vamos estao sejam fosse tenho
fazia dizia podia sabia tinha vinha ouvia seria teria faria diria feito visto posto cante
venha tenha saiba possa estou ficam viram foram deram disse quero vemos lemos
acola agudo alias amora apelo apito ardor asilo baixa banal barba boato bocal boina bolor
bonde cabos caqui carpa cento cerne cetim chale cheio cifra cisco citar colmo crase cutia
debil depor dique droga ebrio ereto esqui fecho feixe feudo fisga fossa gabar galao gelar
gemer gerar gozar graxa grego grife guiar ileso impor jirau laico lhama limar lixar lotar
lotus macho madre magoa malte mamar meiga menos mirim mocho moido nevar ninar notar obeso
ocaso odiar optar outra parir pasmo pecar pegar penal perua pinto plena porem prole quota
raiar ralar rapto raros rasto reter rever rezar rimar rocar rodar rolar ruiva sacar salmo
salvo seita selar selim senil silvo sonar sorvo sueco tapar tenor terco tomba topar trair
treta truco untar vadio vagar vaiar valer vazar vedar velar venus vetar viela vinda vindo
zerar zumbi
`;

function parseWords(text) {
    return [...new Set(
        text.split(/\s+/)
            .map(word => normalizeWord(word))
            .filter(word => /^[a-z]{5}$/.test(word))
    )];
}

// Remove acentos e cedilha; mantém só letras minúsculas
function normalizeWord(value) {
    return String(value || "")
        .normalize("NFD")
        .replace(/[̀-ͯ]/g, "")
        .toLowerCase()
        .replace(/[^a-z]/g, "");
}

const ANSWERS = parseWords(ANSWERS_TEXT);
// Palavras extras do dicionário aberto (arquivo de dados ao lado; linhas com # são comentários)
const DICTIONARY_TEXT = require("fs")
    .readFileSync(require("path").join(__dirname, "minigame-dicionario.txt"), "utf8")
    .split("\n")
    .map(line => line.trim())
    .filter(line => !line.startsWith("#"))
    .join(" ");

const VALID_GUESSES = new Set([...ANSWERS, ...parseWords(EXTRA_GUESSES_TEXT), ...parseWords(DICTIONARY_TEXT)]);

module.exports = {
    ANSWERS,
    VALID_GUESSES,
    normalizeWord
};
