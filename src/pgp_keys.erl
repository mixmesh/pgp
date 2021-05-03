%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Generate PGP keys
%%% @end
%%% Created :  1 May 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_keys).

-export([generate_rsa_key/0, generate_rsa_key/2]).
-export([generate_dss_key/0, generate_dss_key/1]).
-export([generate_elgamal_key/0, generate_elgamal_key/1]).
-export([generate_mixmesh_key/0, generate_mixmesh_key/1]).

-include_lib("elgamal/include/elgamal.hrl").

-type public_rsa() :: map().
-type private_rsa() :: map().

-type public_dss() :: map().
-type private_dss() :: map().

-type public_elgamal() :: map().
-type private_elgamal() :: map().

generate_rsa_key() ->
    generate_rsa_key(2048, 65537).

-spec generate_rsa_key(ModulusSizeInBits::integer(), 
		       PublicExponent :: integer()) ->
	  {public_rsa(), private_rsa()}.
	  
generate_rsa_key(ModulusSizeInBits, PublicExponent) ->
    {[E,N],[E, N, D, P1, P2, _E1, _E2, C]} =
	crypto:generate_key(rsa, {ModulusSizeInBits, PublicExponent}),
    Public = #{ type => rsa,
		use => [encrypt,sign],
		creation => calendar:universal_time(),
		e => binary:decode_unsigned(E, big),
		n => binary:decode_unsigned(N, big) },
    Private = Public#{ d => binary:decode_unsigned(D, big),
		       p => binary:decode_unsigned(P1, big),
		       q => binary:decode_unsigned(P2, big),
		       u => binary:decode_unsigned(C, big) },
    {Public, Private}.

generate_mixmesh_key() ->
    generate_mixmesh_key(1024).

generate_mixmesh_key(old) ->
    G = ?G_OLD,
    P = ?P_OLD,
    generate_mixmesh_key(P,G);
generate_mixmesh_key(512) ->
    G = ?G_512,
    P = ?P_512,
    generate_mixmesh_key(P,G);
generate_mixmesh_key(1024) ->
    G = ?G_1024,
    P = ?P_1024,
    generate_mixmesh_key(P,G).

generate_mixmesh_key(P,G) ->
    generate_dh_key__(elgamal, [encrypt], P,(P-1) div 2, G).
    
generate_elgamal_key() ->
    generate_elgamal_key(2048).

-spec generate_elgamal_key(Size :: integer()) ->
	  {public_elgamal(), private_elgamal()}.

 %% FIXME: only when dh key P is safe prime (Q = (P-1) div 2)
generate_elgamal_key(Size) ->
    generate_dh_key_(elgamal, [encrypt], Size).

generate_dss_key() ->
    generate_dss_key(2048).

-spec generate_dss_key(Size :: integer()) ->
	  {public_dss(), private_dss()}.

generate_dss_key(Size) ->
    generate_dh_key_(dss, [sign], Size).

generate_dh_key_(Type, Use, Size) ->
    ID = dh_size_to_group(Size),
    G = dh_group_to_g(ID),
    P = dh_group_to_p(ID),
    Q = (P-1) div 2,
    P = Q*2+1,  %% validation
    generate_dh_key__(Type, Use, P, Q, G).

generate_dh_key__(Type, Use, P, Q, G) ->
    {Yb,Xb} = crypto:generate_key(dh, [P, G]),
    Y = binary:decode_unsigned(Yb, big),
    X = binary:decode_unsigned(Xb, big),
    Y = mpz:powm(G, X, P),  %% validation
    Public = #{ type => Type, use => Use,
		creation => calendar:universal_time(),
		p => P,
		q => Q,
		g => G,
		y => Y },
    Private = Public#{ x => X },
    {Public, Private }.

dh_size_to_group(768) -> 1;
dh_size_to_group(1536) -> 5;
dh_size_to_group(2048) -> 14;
dh_size_to_group(3072) -> 15;
dh_size_to_group(4096) -> 16;
dh_size_to_group(6144) -> 17;
dh_size_to_group(8192) -> 18.

dh_group_to_g(_) -> 2.

%% FIXME: add keys from https://tools.ietf.org/html/rfc7919?

%% ID = 1, G=2, SIZE=768
dh_group_to_p(1) ->
    16#FFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1_29024E08_8A67CC74_020BBEA6_3B139B22_514A0879_8E3404DD_EF9519B3_CD3A431B_302B0A6D_F25F1437_4FE1356D_6D51C245_E485B576_625E7EC6_F44C42E9_A63A3620_FFFFFFFF_FFFFFFFF;

%% ID = 5, G=2, SIZE=1536
dh_group_to_p(5) ->
    16#FFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1_29024E08_8A67CC74_020BBEA6_3B139B22_514A0879_8E3404DD_EF9519B3_CD3A431B_302B0A6D_F25F1437_4FE1356D_6D51C245_E485B576_625E7EC6_F44C42E9_A637ED6B_0BFF5CB6_F406B7ED_EE386BFB_5A899FA5_AE9F2411_7C4B1FE6_49286651_ECE45B3D_C2007CB8_A163BF05_98DA4836_1C55D39A_69163FA8_FD24CF5F_83655D23_DCA3AD96_1C62F356_208552BB_9ED52907_7096966D_670C354E_4ABC9804_F1746C08_CA237327_FFFFFFFF_FFFFFFFF;
%% ID = 14, G=2, SIZE=2048
dh_group_to_p(14) ->
    16#FFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1_29024E08_8A67CC74_020BBEA6_3B139B22_514A0879_8E3404DD_EF9519B3_CD3A431B_302B0A6D_F25F1437_4FE1356D_6D51C245_E485B576_625E7EC6_F44C42E9_A637ED6B_0BFF5CB6_F406B7ED_EE386BFB_5A899FA5_AE9F2411_7C4B1FE6_49286651_ECE45B3D_C2007CB8_A163BF05_98DA4836_1C55D39A_69163FA8_FD24CF5F_83655D23_DCA3AD96_1C62F356_208552BB_9ED52907_7096966D_670C354E_4ABC9804_F1746C08_CA18217C_32905E46_2E36CE3B_E39E772C_180E8603_9B2783A2_EC07A28F_B5C55DF0_6F4C52C9_DE2BCBF6_95581718_3995497C_EA956AE5_15D22618_98FA0510_15728E5A_8AACAA68_FFFFFFFF_FFFFFFFF;
%% ID = 15, G=2, SIZE=3072
dh_group_to_p(15) ->
    16#FFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1_29024E08_8A67CC74_020BBEA6_3B139B22_514A0879_8E3404DD_EF9519B3_CD3A431B_302B0A6D_F25F1437_4FE1356D_6D51C245_E485B576_625E7EC6_F44C42E9_A637ED6B_0BFF5CB6_F406B7ED_EE386BFB_5A899FA5_AE9F2411_7C4B1FE6_49286651_ECE45B3D_C2007CB8_A163BF05_98DA4836_1C55D39A_69163FA8_FD24CF5F_83655D23_DCA3AD96_1C62F356_208552BB_9ED52907_7096966D_670C354E_4ABC9804_F1746C08_CA18217C_32905E46_2E36CE3B_E39E772C_180E8603_9B2783A2_EC07A28F_B5C55DF0_6F4C52C9_DE2BCBF6_95581718_3995497C_EA956AE5_15D22618_98FA0510_15728E5A_8AAAC42D_AD33170D_04507A33_A85521AB_DF1CBA64_ECFB8504_58DBEF0A_8AEA7157_5D060C7D_B3970F85_A6E1E4C7_ABF5AE8C_DB0933D7_1E8C94E0_4A25619D_CEE3D226_1AD2EE6B_F12FFA06_D98A0864_D8760273_3EC86A64_521F2B18_177B200C_BBE11757_7A615D6C_770988C0_BAD946E2_08E24FA0_74E5AB31_43DB5BFC_E0FD108E_4B82D120_A93AD2CA_FFFFFFFF_FFFFFFFF;
%% ID = 16, G=2, SIZE=4096
dh_group_to_p(16) ->
    16#FFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1_29024E08_8A67CC74_020BBEA6_3B139B22_514A0879_8E3404DD_EF9519B3_CD3A431B_302B0A6D_F25F1437_4FE1356D_6D51C245_E485B576_625E7EC6_F44C42E9_A637ED6B_0BFF5CB6_F406B7ED_EE386BFB_5A899FA5_AE9F2411_7C4B1FE6_49286651_ECE45B3D_C2007CB8_A163BF05_98DA4836_1C55D39A_69163FA8_FD24CF5F_83655D23_DCA3AD96_1C62F356_208552BB_9ED52907_7096966D_670C354E_4ABC9804_F1746C08_CA18217C_32905E46_2E36CE3B_E39E772C_180E8603_9B2783A2_EC07A28F_B5C55DF0_6F4C52C9_DE2BCBF6_95581718_3995497C_EA956AE5_15D22618_98FA0510_15728E5A_8AAAC42D_AD33170D_04507A33_A85521AB_DF1CBA64_ECFB8504_58DBEF0A_8AEA7157_5D060C7D_B3970F85_A6E1E4C7_ABF5AE8C_DB0933D7_1E8C94E0_4A25619D_CEE3D226_1AD2EE6B_F12FFA06_D98A0864_D8760273_3EC86A64_521F2B18_177B200C_BBE11757_7A615D6C_770988C0_BAD946E2_08E24FA0_74E5AB31_43DB5BFC_E0FD108E_4B82D120_A9210801_1A723C12_A787E6D7_88719A10_BDBA5B26_99C32718_6AF4E23C_1A946834_B6150BDA_2583E9CA_2AD44CE8_DBBBC2DB_04DE8EF9_2E8EFC14_1FBECAA6_287C5947_4E6BC05D_99B2964F_A090C3A2_233BA186_515BE7ED_1F612970_CEE2D7AF_B81BDD76_2170481C_D0069127_D5B05AA9_93B4EA98_8D8FDDC1_86FFB7DC_90A6C08F_4DF435C9_34063199_FFFFFFFF_FFFFFFFF;
%% ID = 17, G=2, SIZE=6144
dh_group_to_p(17) ->
    16#FFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1_29024E08_8A67CC74_020BBEA6_3B139B22_514A0879_8E3404DD_EF9519B3_CD3A431B_302B0A6D_F25F1437_4FE1356D_6D51C245_E485B576_625E7EC6_F44C42E9_A637ED6B_0BFF5CB6_F406B7ED_EE386BFB_5A899FA5_AE9F2411_7C4B1FE6_49286651_ECE45B3D_C2007CB8_A163BF05_98DA4836_1C55D39A_69163FA8_FD24CF5F_83655D23_DCA3AD96_1C62F356_208552BB_9ED52907_7096966D_670C354E_4ABC9804_F1746C08_CA18217C_32905E46_2E36CE3B_E39E772C_180E8603_9B2783A2_EC07A28F_B5C55DF0_6F4C52C9_DE2BCBF6_95581718_3995497C_EA956AE5_15D22618_98FA0510_15728E5A_8AAAC42D_AD33170D_04507A33_A85521AB_DF1CBA64_ECFB8504_58DBEF0A_8AEA7157_5D060C7D_B3970F85_A6E1E4C7_ABF5AE8C_DB0933D7_1E8C94E0_4A25619D_CEE3D226_1AD2EE6B_F12FFA06_D98A0864_D8760273_3EC86A64_521F2B18_177B200C_BBE11757_7A615D6C_770988C0_BAD946E2_08E24FA0_74E5AB31_43DB5BFC_E0FD108E_4B82D120_A9210801_1A723C12_A787E6D7_88719A10_BDBA5B26_99C32718_6AF4E23C_1A946834_B6150BDA_2583E9CA_2AD44CE8_DBBBC2DB_04DE8EF9_2E8EFC14_1FBECAA6_287C5947_4E6BC05D_99B2964F_A090C3A2_233BA186_515BE7ED_1F612970_CEE2D7AF_B81BDD76_2170481C_D0069127_D5B05AA9_93B4EA98_8D8FDDC1_86FFB7DC_90A6C08F_4DF435C9_34028492_36C3FAB4_D27C7026_C1D4DCB2_602646DE_C9751E76_3DBA37BD_F8FF9406_AD9E530E_E5DB382F_413001AE_B06A53ED_9027D831_179727B0_865A8918_DA3EDBEB_CF9B14ED_44CE6CBA_CED4BB1B_DB7F1447_E6CC254B_33205151_2BD7AF42_6FB8F401_378CD2BF_5983CA01_C64B92EC_F032EA15_D1721D03_F482D7CE_6E74FEF6_D55E702F_46980C82_B5A84031_900B1C9E_59E7C97F_BEC7E8F3_23A97A7E_36CC88BE_0F1D45B7_FF585AC5_4BD407B2_2B4154AA_CC8F6D7E_BF48E1D8_14CC5ED2_0F8037E0_A79715EE_F29BE328_06A1D58B_B7C5DA76_F550AA3D_8A1FBFF0_EB19CCB1_A313D55C_DA56C9EC_2EF29632_387FE8D7_6E3C0468_043E8F66_3F4860EE_12BF2D5B_0B7474D6_E694F91E_6DCC4024_FFFFFFFF_FFFFFFFF;
%% ID = 18, G=2, SIZE=8192
dh_group_to_p(18) ->
    16#FFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1_29024E08_8A67CC74_020BBEA6_3B139B22_514A0879_8E3404DD_EF9519B3_CD3A431B_302B0A6D_F25F1437_4FE1356D_6D51C245_E485B576_625E7EC6_F44C42E9_A637ED6B_0BFF5CB6_F406B7ED_EE386BFB_5A899FA5_AE9F2411_7C4B1FE6_49286651_ECE45B3D_C2007CB8_A163BF05_98DA4836_1C55D39A_69163FA8_FD24CF5F_83655D23_DCA3AD96_1C62F356_208552BB_9ED52907_7096966D_670C354E_4ABC9804_F1746C08_CA18217C_32905E46_2E36CE3B_E39E772C_180E8603_9B2783A2_EC07A28F_B5C55DF0_6F4C52C9_DE2BCBF6_95581718_3995497C_EA956AE5_15D22618_98FA0510_15728E5A_8AAAC42D_AD33170D_04507A33_A85521AB_DF1CBA64_ECFB8504_58DBEF0A_8AEA7157_5D060C7D_B3970F85_A6E1E4C7_ABF5AE8C_DB0933D7_1E8C94E0_4A25619D_CEE3D226_1AD2EE6B_F12FFA06_D98A0864_D8760273_3EC86A64_521F2B18_177B200C_BBE11757_7A615D6C_770988C0_BAD946E2_08E24FA0_74E5AB31_43DB5BFC_E0FD108E_4B82D120_A9210801_1A723C12_A787E6D7_88719A10_BDBA5B26_99C32718_6AF4E23C_1A946834_B6150BDA_2583E9CA_2AD44CE8_DBBBC2DB_04DE8EF9_2E8EFC14_1FBECAA6_287C5947_4E6BC05D_99B2964F_A090C3A2_233BA186_515BE7ED_1F612970_CEE2D7AF_B81BDD76_2170481C_D0069127_D5B05AA9_93B4EA98_8D8FDDC1_86FFB7DC_90A6C08F_4DF435C9_34028492_36C3FAB4_D27C7026_C1D4DCB2_602646DE_C9751E76_3DBA37BD_F8FF9406_AD9E530E_E5DB382F_413001AE_B06A53ED_9027D831_179727B0_865A8918_DA3EDBEB_CF9B14ED_44CE6CBA_CED4BB1B_DB7F1447_E6CC254B_33205151_2BD7AF42_6FB8F401_378CD2BF_5983CA01_C64B92EC_F032EA15_D1721D03_F482D7CE_6E74FEF6_D55E702F_46980C82_B5A84031_900B1C9E_59E7C97F_BEC7E8F3_23A97A7E_36CC88BE_0F1D45B7_FF585AC5_4BD407B2_2B4154AA_CC8F6D7E_BF48E1D8_14CC5ED2_0F8037E0_A79715EE_F29BE328_06A1D58B_B7C5DA76_F550AA3D_8A1FBFF0_EB19CCB1_A313D55C_DA56C9EC_2EF29632_387FE8D7_6E3C0468_043E8F66_3F4860EE_12BF2D5B_0B7474D6_E694F91E_6DBE1159_74A3926F_12FEE5E4_38777CB6_A932DF8C_D8BEC4D0_73B931BA_3BC832B6_8D9DD300_741FA7BF_8AFC47ED_2576F693_6BA42466_3AAB639C_5AE4F568_3423B474_2BF1C978_238F16CB_E39D652D_E3FDB8BE_FC848AD9_22222E04_A4037C07_13EB57A8_1A23F0C7_3473FC64_6CEA306B_4BCBC886_2F8385DD_FA9D4B7F_A2C087E8_79683303_ED5BDD3A_062B3CF5_B3A278A6_6D2A13F8_3F44F82D_DF310EE0_74AB6A36_4597E899_A0255DC1_64F31CC5_0846851D_F9AB4819_5DED7EA1_B1D510BD_7EE74D73_FAF36BC3_1ECFA268_359046F4_EB879F92_4009438B_481C6CD7_889A002E_D5EE382B_C9190DA6_FC026E47_9558E447_5677E9AA_9E3050E2_765694DF_C81F56E8_80B96E71_60C980DD_98EDD3DF_FFFFFFFF_FFFFFFFF.
