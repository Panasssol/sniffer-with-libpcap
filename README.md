# sniffer

O [sniffer escolhido](https://github.com/homoluctus/sniffer-with-libpcap) possuia suporte para IPv4, TCP, UDP e Ethernet, cada um com seu respectivo código para realizar a exibição dos cabeçalhos.

Desenvolvido em C, utilizando a biblioteca libpcap e focado no Ubuntu 16.04.3 LTS.

Adicionei o suporte para IPv6 com a exibição do seu cabeçalho, além de juntar as outras funcionalidades a verificação de IPv4, TCP e UDP no mesmo arquivo para que tudo seja analisado junto. Não foi adicionada a exibição do protocolo de Ethernet pois eram exibidos pacotes demais, o que dificultava a visualização dos outros pacotes.