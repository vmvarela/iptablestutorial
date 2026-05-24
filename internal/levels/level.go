package levels

// Red describe la topología de red de un nivel.
type Red struct {
	FirewallIP string     `yaml:"firewall_ip"` // IP del propio firewall (el castillo)
	Interfaces []Interfaz `yaml:"interfaces"`
	Hosts      []Host     `yaml:"hosts"`
}

// Interfaz es una interfaz de red del firewall en un nivel.
type Interfaz struct {
	Nombre string `yaml:"nombre"`
	Zona   string `yaml:"zona"` // "barrio", "mundo", "dmz"
	CIDR   string `yaml:"cidr"`
	IP     string `yaml:"ip"` // IP del firewall en esta interfaz (opcional)
}

// Host es un host virtual en el nivel.
type Host struct {
	Nombre string `yaml:"nombre"`
	IP     string `yaml:"ip"`
	Zona   string `yaml:"zona"`
	Iface  string `yaml:"iface"` // nombre de interfaz del firewall
}

// Prueba define una condición de éxito verificable para un nivel.
type Prueba struct {
	Descripcion string `yaml:"descripcion"`
	SrcIP       string `yaml:"src_ip"`
	DstIP       string `yaml:"dst_ip"`
	DstPort     int    `yaml:"dst_port"`
	Proto       string `yaml:"proto"`     // "tcp","udp","icmp"
	Estado      string `yaml:"estado"`    // "NEW","ESTABLISHED", etc.
	InIface     string `yaml:"in_iface"`  // opcional: interfaz de entrada forzada
	OutIface    string `yaml:"out_iface"` // opcional: interfaz de salida forzada
	Esperado    string `yaml:"esperado"`  // "ACCEPT","DROP","REJECT"
}

// Level es una aventura del juego.
type Level struct {
	ID              string            `yaml:"id"`
	Titulo          string            `yaml:"titulo"`
	Cuento          string            `yaml:"cuento"`           // texto narrativo largo
	Mision          string            `yaml:"mision"`           // objetivo breve
	Red             Red               `yaml:"red"`
	Politicas       map[string]string `yaml:"politicas"`        // chain→"ACCEPT"|"DROP"
	ReglasIniciales []string          `yaml:"reglas_iniciales"` // comandos iptables pre-cargados
	Pistas          []string          `yaml:"pistas"`
	Pruebas         []Prueba          `yaml:"pruebas"`
	Recompensa      string            `yaml:"recompensa"`
}
