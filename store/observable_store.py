class ObservableStore:
    def __init__(self, df):
        self.df = df

    def get_ips(self):
        return set(self.df["src_ip"]).union(set(self.df["dst_ip"]))

    def get_dns_queries(self):
        return self.df["dns_query"].dropna().unique()

    def get_ports(self):
        return self.df[["src_port", "dst_port"]]
