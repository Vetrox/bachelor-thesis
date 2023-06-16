#include "input.h"
#include "affine_point.h"
#include "jacobi_elliptic_curve.h"

Input setup_input()
{
    return {
        .server_random = {0x64, 0x8b, 0x81, 0x0c, 0xe8, 0x1b, 0x88, 0x92, 0x82, 0x7f, 0x4c, 0x61, 0x48, 0x3e, 0x12, 0x4c, 0x9a, 0x0f, 0xe3, 0x06, 0xea, 0x93, 0xa0, 0x19, 0x7c, 0x01, 0x39, 0x89, 0x02, 0x02, 0xb5, 0xae},
        .client_random = {0x64, 0x8b, 0x81, 0x0c, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b,0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b},
        .server_session_id = {0x9c, 0x5e, 0x79, 0xd7, 0x7b, 0x1e, 0xcd, 0x5a, 0xd6, 0x1d, 0xbf, 0xf7, 0xca, 0xd0, 0x4a, 0x7b, 0x4a, 0x81, 0x5e, 0x01, 0xf0, 0x65, 0x02, 0x36, 0x02, 0xf2, 0x74, 0xaa, 0x5b, 0x2f, 0x03, 0x67},
        .dh_generator = 2,
        .dh_prime = BigInt("32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559"),
        .dh_bitlen_of_a = 2048, // TODO: NOT LEAKED
        .dh_pubkey_server = BigInt("3402338783148726887703179594391818335843878103415959364078773610092793116078976252832133707241792017540882438679946031516994558163877775727529332273049542644417975703942956389490598313293328791454101893192920722588748809930415825491671125327736357265982637787740715049251506088300697613297841989873316953923284194735028040976554153588889590382791594381395067949246291791862733105744200100344956999214897577918179859380037210102152871099631777281642166489531666005136744308538152636756734098126340498683644085548077833282378592183892544914982620608127865412620449751778875929533447061025179068941703966182373987639569"),
        .dh_pubkey_client = BigInt("10806753991619465624697251087749140953869036931800087975410557214108313368395952159040279610394408055845029151434625839960274790264456424301597812365298856503048009690027681167905475124605527995991135886397928105322212736211060868391764252762981791678422274571075733818057585882699400623827199555958909745648527909835303969097579471054385980625544938530693964656717387499305120036755941581266323307679184311734306595526672209089435087989260953932077000271938415146642559378341775707205095864430818954514480503724536027625977632220810845656550053436636731237542641828678658641563403960038033426057077830133210002607068"),
        .dec_security_strength = 128,
        .dec_curve = {
            .curve = JacobiEllipticCurve(
                    BigInt("115792089210356248762697446949407573530086143415290314195533631308867097853951"),
                    BigInt("41058363725152142129326129780047268409114441015993725554835256314039467401291")),
            .P = AffinePoint(
                    BigInt("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
                    BigInt("36134250956749795798585127919587881956611106672985015071877198253568414405109")),
            .order_of_p = BigInt("115792089210356248762697446949407573529996955224135760342422259061068512044369"), // TODO: CAN BE CALCULATED
            .Q = AffinePoint(BigInt("58122190547351619314832142482958009588534653900841396129684563264131116700560"), BigInt("53567662391920079536836225565042724814092473002585219702054150877606765064388")),
        },
        .dec_secret_d = 0x10ed1df5,
        .dec_adin = BitStr(0), // TODO: replace with optional empty later
    .msg_iv_offset = 1,
    .msg_container = {0x97, 0xe3, 0x3c, 0xb3, 0x52, 0x30, 0x1e, 0xde, 0x02, 0x8b, 0xf6, 0x3e, 0x99, 0xcf, 0xd0, 0x88, 0x25, 0xa0, 0x1d, 0xfd, 0xd5, 0xb3, 0x98, 0xc8, 0xe4, 0xa9, 0x2f, 0x88, 0x8c, 0x05, 0x9d, 0xae, 0xee, 0x01}
    };
}


