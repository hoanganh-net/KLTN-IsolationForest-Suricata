# -*- coding: utf-8 -*-
"""
isolationforest.py — Isolation Forest TỰ CÀI (NumPy thuần, không dùng scikit-learn).

Mục đích: dùng trong các notebook của KLTN để CHO THẤY và KIỂM CHỨNG rằng thuật toán
được hiểu đúng từ gốc, không dùng như hộp đen; kèm z-score diễn giải (zscore/explain/explain_str)
đã gộp vào đây. File runtime `anomaly.py` thì dùng bản
Isolation Forest của scikit-learn cho tốc độ; hai bản được đối chiếu bằng tương quan
thứ hạng Spearman (xem hàm so sánh ở cuối notebook).

Mạch triển khai nối tiếp từ test.ipynb:
  split_data()  -> chọn ngẫu nhiên một đặc trưng, lấy min/max, bốc ngưỡng ngẫu nhiên,
                   chia dữ liệu thành nhánh trái/phải.
  Node          -> một nút của cây: feature_index, threshold, left, right, is_leaf, size.
  iTree         -> đệ quy split_data cho tới khi cô lập (1 điểm) hoặc chạm giới hạn độ cao.
  Forest        -> gồm nhiều iTree, mỗi cây học trên một mẫu con psi điểm lấy ngẫu nhiên.
  Chấm điểm     -> E(h(x)) là độ dài đường đi trung bình; s = 2^(-E/c(psi)).

Công thức (Liu, Ting, Zhou 2008):
  c(n) = 2*H(n-1) - 2*(n-1)/n ,  với H(i) = ln(i) + gamma (gamma ~ 0.5772, hằng Euler).
         c(n) là độ dài đường đi trung bình kỳ vọng trong cây tìm kiếm nhị phân không
         thành công trên n điểm -> dùng để CHUẨN HÓA điểm, cho các cỡ mẫu so sánh được.
  s(x) = 2^( -E(h(x)) / c(psi) ) ,  s -> 1: bất thường rõ; s ~ 0.5: trung bình;
         s < 0.5 hẳn: nằm sâu trong vùng bình thường.
"""

import numpy as np

EULER_GAMMA = 0.5772156649015329


def c_factor(n):
    """Độ dài đường đi trung bình kỳ vọng c(n) để chuẩn hóa điểm (một giá trị).
    n là số điểm đi tới một nút lá (hoặc cỡ mẫu con psi)."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    H = np.log(n - 1) + EULER_GAMMA           # H(n-1)
    return 2.0 * H - 2.0 * (n - 1) / n


def c_factor_arr(n):
    """Như c_factor nhưng tính cho CẢ MẢNG n (vector hóa, để chấm điểm nhanh)."""
    n = np.asarray(n, dtype=float)
    c = np.zeros_like(n)
    two = (n == 2)
    big = (n > 2)
    c[two] = 1.0
    H = np.log(n[big] - 1.0) + EULER_GAMMA
    c[big] = 2.0 * H - 2.0 * (n[big] - 1.0) / n[big]
    return c


# =============================================================================
# MỘT CÂY CÔ LẬP (iTree)
# =============================================================================
class IsolationTree:
    """Một cây cô lập. Nút được lưu trong các mảng song song để chấm điểm nhanh,
    nhưng logic xây cây vẫn đúng mạch split_data/Node ở test.ipynb."""

    def __init__(self, height_limit, rng):
        self.height_limit = height_limit      # chặn độ cao ~ ceil(log2(psi))
        self.rng = rng                        # bộ sinh ngẫu nhiên (tái lập được)
        # các mảng mô tả nút; chỉ số nút = vị trí trong mảng
        self.feature = []     # đặc trưng được chọn để chia; -1 nếu là lá
        self.threshold = []   # ngưỡng chia
        self.left = []        # chỉ số nút con trái
        self.right = []       # chỉ số nút con phải
        self.size = []        # số điểm tới nút (dùng ở lá để cộng c(size))

    def _new_node(self):
        self.feature.append(-1); self.threshold.append(0.0)
        self.left.append(-1); self.right.append(-1); self.size.append(0)
        return len(self.feature) - 1

    def _build(self, X, height):
        """Dựng đệ quy. X: mảng (n, m) các điểm tới nút này. Trả về chỉ số nút."""
        node = self._new_node()
        n = X.shape[0]
        self.size[node] = n

        # Điều kiện DỪNG -> lá: hết độ cao, chỉ còn <=1 điểm, hoặc mọi điểm trùng nhau.
        if height >= self.height_limit or n <= 1:
            self.feature[node] = -1
            return node

        # --- split_data: chọn đặc trưng ngẫu nhiên, lấy min/max, bốc ngưỡng ngẫu nhiên ---
        m = X.shape[1]
        # chỉ xét các đặc trưng còn biến thiên (min < max); nếu không còn thì thành lá
        cols = [j for j in range(m) if X[:, j].min() < X[:, j].max()]
        if not cols:
            self.feature[node] = -1
            return node
        f = cols[self.rng.integers(0, len(cols))]
        vmin = X[:, f].min(); vmax = X[:, f].max()
        thr = self.rng.uniform(vmin, vmax)

        # --- chia dữ liệu thành trái (< ngưỡng) và phải (>= ngưỡng) ---
        go_left = X[:, f] < thr
        self.feature[node] = f
        self.threshold[node] = thr
        self.left[node] = self._build(X[go_left], height + 1)
        self.right[node] = self._build(X[~go_left], height + 1)
        return node

    def fit(self, X):
        X = np.asarray(X, dtype=float)
        self._build(X, 0)
        # cố định thành mảng numpy để chấm điểm nhanh
        self.feature = np.asarray(self.feature, dtype=int)
        self.threshold = np.asarray(self.threshold, dtype=float)
        self.left = np.asarray(self.left, dtype=int)
        self.right = np.asarray(self.right, dtype=int)
        self.size = np.asarray(self.size, dtype=int)
        return self

    def path_length(self, X):
        """Độ dài đường đi h(x) cho từng điểm trong X (mảng (N,m)).
        Đưa CẢ loạt điểm đi xuống cây cùng lúc (vector hóa) để nhanh;
        tại lá cộng thêm c(size) để bù phần cây chưa dựng hết."""
        X = np.asarray(X, dtype=float)
        N = X.shape[0]
        node = np.zeros(N, dtype=int)      # mọi điểm bắt đầu ở gốc (nút 0)
        depth = np.zeros(N, dtype=float)
        done = np.zeros(N, dtype=bool)
        adj = np.zeros(N, dtype=float)     # phần cộng thêm c(size) ở lá

        # lặp tối đa theo giới hạn độ cao (cây nông nên vài vòng là xong)
        for _ in range(self.height_limit + 2):
            f = self.feature[node]
            at_leaf = (f == -1) & (~done)
            if at_leaf.any():
                adj[at_leaf] = c_factor_arr(self.size[node[at_leaf]])
                done[at_leaf] = True
            internal = (f != -1) & (~done)
            if not internal.any():
                break
            idx = np.where(internal)[0]
            fi = self.feature[node[idx]]
            xi = X[idx, fi]
            go_left = xi < self.threshold[node[idx]]
            nxt = np.where(go_left, self.left[node[idx]], self.right[node[idx]])
            node[idx] = nxt
            depth[idx] += 1.0
        # điểm nào còn sót (hiếm) thì cũng cộng c(size) tại nút hiện thời
        if not done.all():
            rest = np.where(~done)[0]
            adj[rest] = c_factor_arr(self.size[node[rest]])
        return depth + adj


# =============================================================================
# RỪNG CÔ LẬP (Isolation Forest)
# =============================================================================
class IsolationForest:
    """Isolation Forest tự cài. API gần với scikit-learn để notebook dễ đối chiếu:
        fit(X) ; anomaly_score(X) -> s trong [0,1], càng lớn càng bất thường.
    Tham số mặc định theo bài báo gốc: n_estimators=100, max_samples=256."""

    def __init__(self, n_estimators=100, max_samples=256, random_state=None):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.random_state = random_state
        self.trees = []
        self._psi = None

    def fit(self, X):
        X = np.asarray(X, dtype=float)
        n = X.shape[0]
        rng = np.random.default_rng(self.random_state)
        psi = min(self.max_samples, n)        # cỡ mẫu con thực tế
        self._psi = psi
        height_limit = int(np.ceil(np.log2(max(psi, 2))))  # ~ log2(psi)
        self.trees = []
        for _ in range(self.n_estimators):
            # mỗi cây học trên một mẫu con psi điểm lấy ngẫu nhiên KHÔNG lặp
            idx = rng.choice(n, size=psi, replace=False)
            tree = IsolationTree(height_limit, rng)
            tree.fit(X[idx])
            self.trees.append(tree)
        return self

    def _mean_path(self, X):
        X = np.asarray(X, dtype=float)
        total = np.zeros(X.shape[0], dtype=float)
        for tree in self.trees:
            total += tree.path_length(X)
        return total / len(self.trees)        # E(h(x))

    def anomaly_score(self, X):
        """s(x) = 2^(-E(h(x))/c(psi)). Càng gần 1 càng bất thường."""
        E = self._mean_path(X)
        return np.power(2.0, -E / c_factor(self._psi))


# =============================================================================
# DIỄN GIẢI "VÌ SAO BẤT THƯỜNG" (z-score bền vững — gộp từ zscore.py)
# =============================================================================
# Isolation Forest chỉ cho ĐIỂM bất thường, không nói đặc trưng nào gây ra. Phần dưới bù
# điều đó bằng z = (x - tâm)/thang. Khi DIỄN GIẢI dùng tâm=median, thang=1.4826*MAD (bền
# với chính các điểm bất thường). Nhiều đặc trưng đếm gần như luôn = 0 ở lưu lượng lành nên
# MAD ≈ 0; khi đó |z| bị chặn ở `clip` cho dễ đọc (không ảnh hưởng quyết định của model).

def zscore(x, center, scale):
    """Chuẩn hóa: (x - tâm) / thang. Thang ~0 -> 1 để khỏi chia cho 0."""
    scale = np.where(np.asarray(scale, float) < 1e-9, 1.0, scale)
    return (np.asarray(x, float) - center) / scale


def explain(x, center, scale, feature_names, k=3, clip=50.0):
    """VÌ SAO một mẫu bất thường: trả k đặc trưng lệch xa nhất theo z, giữ |z| > 1, giảm dần theo |z|."""
    z = np.clip(zscore(x, center, scale), -clip, clip)
    order = sorted(range(len(feature_names)), key=lambda j: -abs(z[j]))[:k]
    return [[feature_names[j], round(float(z[j]), 1)] for j in order if abs(z[j]) > 1]


def explain_str(x, center, scale, feature_names, k=3):
    """Như explain() nhưng trả chuỗi gọn để in, ví dụ: 'svc_rarity(+18.2), sqrt_mb_out(+12.7)'."""
    return ", ".join(f"{f}({z:+.1f})" for f, z in explain(x, center, scale, feature_names, k))


# =============================================================================
# TỰ KIỂM TRA NHANH (chạy trực tiếp file này)
# =============================================================================
if __name__ == "__main__":
    rng = np.random.default_rng(0)
    # 200 điểm bình thường quanh gốc + 5 điểm bất thường ở xa
    normal = rng.normal(0, 1, size=(200, 2))
    outliers = np.array([[8, 8], [9, -9], [-8, 8], [10, 10], [-9, -9]], dtype=float)
    X = np.vstack([normal, outliers])

    clf = IsolationForest(n_estimators=100, max_samples=256, random_state=42).fit(X)
    s = clf.anomaly_score(X)
    print("Điểm trung bình (bình thường):", round(float(s[:200].mean()), 3))
    print("Điểm trung bình (bất thường):", round(float(s[200:].mean()), 3))
    # 5 điểm bất thường phải có điểm cao nhất
    top5 = set(np.argsort(s)[-5:].tolist())
    print("5 điểm điểm cao nhất có đúng là 5 outlier không:",
          top5 == set(range(200, 205)))
